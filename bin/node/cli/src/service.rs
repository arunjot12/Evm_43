// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

#![warn(unused_extern_crates)]

//! Service implementation. Specialized wrapper over substrate service.

use crate::Cli;
use sc_client_api::BlockBackend;
use codec::Encode;
use frame_benchmarking_cli::SUBSTRATE_REFERENCE_HARDWARE;
use frame_system_rpc_runtime_api::AccountNonceApi;
use futures::prelude::*;
use node_5ire_runtime::RuntimeApi;
use node_executor::ExecutorDispatch;
use node_primitives::Block;
use crate::rpc::BackendType;
use sc_consensus_babe::{ self, SlotProportion };
use sc_executor::NativeElseWasmExecutor;
use sc_network::{ event::Event, NetworkEventStream, NetworkService };
use sc_network_common::sync::warp::WarpSyncParams;
use sc_network_sync::SyncingService;
use fc_rpc_core::types::FeeHistoryCacheLimit;
use sc_service::{ config::Configuration, error::Error as ServiceError, RpcHandlers, TaskManager };
use sc_telemetry::{ Telemetry, TelemetryWorker };
use sp_api::ProvideRuntimeApi;
use sp_core::crypto::Pair;
use sp_runtime::{ generic, traits::Block as BlockT, SaturatedConversion };
use std::sync::Arc;
use fc_db::Backend as FrontierBackend;
use sc_statement_store::Store as StatementStore;
use std::path::Path;
use std::{ collections::BTreeMap, path::PathBuf, sync::{ Mutex }, time::Duration };
use sc_client_api::BlockchainEvents;
use fc_rpc::EthTask;
use fc_rpc::OverrideHandle;
use crate::rpc::EthConfiguration;
use fc_rpc_core::types::FilterPool;
use fc_rpc_core::types::FeeHistoryCache;
/// The full client type definition.
pub type FullClient = sc_service::TFullClient<
	Block,
	RuntimeApi,
	NativeElseWasmExecutor<ExecutorDispatch>
>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;
type FullGrandpaBlockImport = grandpa::GrandpaBlockImport<
	FullBackend,
	Block,
	FullClient,
	FullSelectChain
>;

/// The transaction pool type defintion.
pub type TransactionPool = sc_transaction_pool::FullPool<Block, FullClient>;

/// Fetch the nonce of the given `account` from the chain state.
///
/// Note: Should only be used for tests.
pub fn fetch_nonce(client: &FullClient, account: sp_core::sr25519::Pair) -> u32 {
	let best_hash = client.chain_info().best_hash;
	client
		.runtime_api()
		.account_nonce(best_hash, account.public().into())
		.expect("Fetching account nonce works; qed")
}

pub fn db_config_dir(config: &Configuration) -> PathBuf {
	config.base_path.config_dir(config.chain_spec.id())
}

/// Create a transaction using the given `call`.
///
/// The transaction will be signed by `sender`. If `nonce` is `None` it will be fetched from the
/// state of the best block.
///
/// Note: Should only be used for tests.
pub fn create_extrinsic(
	client: &FullClient,
	sender: sp_core::sr25519::Pair,
	function: impl Into<node_5ire_runtime::RuntimeCall>,
	nonce: Option<u32>
) -> node_5ire_runtime::UncheckedExtrinsic {
	let function = function.into();
	let genesis_hash = client.block_hash(0).ok().flatten().expect("Genesis block exists; qed");
	let best_hash = client.chain_info().best_hash;
	let best_block = client.chain_info().best_number;
	let nonce = nonce.unwrap_or_else(|| fetch_nonce(client, sender.clone()));

	let period = node_5ire_runtime::BlockHashCount
		::get()
		.checked_next_power_of_two()
		.map(|c| c / 2)
		.unwrap_or(2) as u64;
	let tip = 0;
	let extra: node_5ire_runtime::SignedExtra = (
		frame_system::CheckNonZeroSender::<node_5ire_runtime::Runtime>::new(),
		frame_system::CheckSpecVersion::<node_5ire_runtime::Runtime>::new(),
		frame_system::CheckTxVersion::<node_5ire_runtime::Runtime>::new(),
		frame_system::CheckGenesis::<node_5ire_runtime::Runtime>::new(),
		frame_system::CheckEra::<node_5ire_runtime::Runtime>::from(
			generic::Era::mortal(period, best_block.saturated_into())
		),
		frame_system::CheckNonce::<node_5ire_runtime::Runtime>::from(nonce),
		frame_system::CheckWeight::<node_5ire_runtime::Runtime>::new(),
		pallet_asset_tx_payment::ChargeAssetTxPayment::<node_5ire_runtime::Runtime>::from(
			tip,
			None
		),
	);

	let raw_payload = node_5ire_runtime::SignedPayload::from_raw(function.clone(), extra.clone(), (
		(),
		node_5ire_runtime::VERSION.spec_version,
		node_5ire_runtime::VERSION.transaction_version,
		genesis_hash,
		best_hash,
		(),
		(),
		(),
	));
	let signature = raw_payload.using_encoded(|e| sender.sign(e));

	node_5ire_runtime::UncheckedExtrinsic::new_signed(
		function,
		sp_runtime::AccountId32::from(sender.public()).into(),
		node_5ire_runtime::Signature::Sr25519(signature),
		extra
	)
}

/// Creates a new partial node.
pub fn new_partial(config: &Configuration) -> Result<
	sc_service::PartialComponents<
		FullClient,
		FullBackend,
		FullSelectChain,
		sc_consensus::DefaultImportQueue<Block, FullClient>,
		sc_transaction_pool::FullPool<Block, FullClient>,
		(
			
			(
				sc_consensus_babe::BabeBlockImport<Block, FullClient, FullGrandpaBlockImport>,
				grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
				sc_consensus_babe::BabeLink<Block>,
				
			),
			// grandpa::SharedVoterState,
			Option<Telemetry>,
			Arc<StatementStore>,
			sc_consensus_babe::BabeWorkerHandle<Block>,	
			FrontierBackend<Block>,
		)
	>,
	ServiceError
> {
	let telemetry = config.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(
			|endpoints| -> Result<_, sc_telemetry::Error> {
				let worker = TelemetryWorker::new(16)?;
				let telemetry = worker.handle().new_telemetry(endpoints);
				Ok((worker, telemetry))
			}
		)
		.transpose()?;

	let executor = sc_service::new_native_or_wasm_executor(&config);

	let (client, backend, keystore_container, task_manager) = sc_service::new_full_parts::<
		Block,
		RuntimeApi,
		_
	>(
		config,
		telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
		executor
	)?;
	let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", None, worker.run());
		telemetry
	});

	let select_chain = sc_consensus::LongestChain::new(backend.clone());

	let transaction_pool = sc_transaction_pool::BasicPool::new_full(
		config.transaction_pool.clone(),
		config.role.is_authority().into(),
		config.prometheus_registry(),
		task_manager.spawn_essential_handle(),
		client.clone()
	);

	let (grandpa_block_import, grandpa_link) = grandpa::block_import(
		client.clone(),
		&(client.clone() as Arc<_>),
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle())
	)?;
	let justification_import = grandpa_block_import.clone();

	let (block_import, babe_link) = sc_consensus_babe::block_import(
		sc_consensus_babe::configuration(&*client)?,
		grandpa_block_import,
		client.clone()
	)?;

	let slot_duration = babe_link.config().slot_duration();
	let (import_queue,babe_worker_handle)  = sc_consensus_babe::import_queue(
		babe_link.clone(),
		block_import.clone(),
		Some(Box::new(justification_import)),
		client.clone(),
		select_chain.clone(),
		move |_, ()| async move {
			let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

			let slot =
				sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
					*timestamp,
					slot_duration
				);

			Ok((slot, timestamp))
		},
		&task_manager.spawn_essential_handle(),
		config.prometheus_registry(),
		telemetry.as_ref().map(|x| x.handle())
	)?;

	// let import = import_queue.0;
	let overrides = crate::rpc::overrides_handle(client.clone());
	let eth: EthConfiguration = Default::default();
	let frontier_backend = match eth.frontier_backend_type {
		BackendType::KeyValue =>
			FrontierBackend::KeyValue(
				fc_db::kv::Backend::open(
					Arc::clone(&client),
					&config.database,
					&db_config_dir(config)
				)?
			),
		BackendType::Sql => {
			let db_path = db_config_dir(config).join("sql");
			std::fs::create_dir_all(&db_path).expect("failed creating sql db directory");
			let backend = futures::executor
				::block_on(
					fc_db::sql::Backend::new(
						fc_db::sql::BackendConfig::Sqlite(fc_db::sql::SqliteBackendConfig {
							path: Path::new("sqlite:///")
								.join(db_path)
								.join("frontier.db3")
								.to_str()
								.unwrap(),
							create_if_missing: true,
							thread_count: eth.frontier_sql_backend_thread_count,
							cache_size: eth.frontier_sql_backend_cache_size,
						}),
						eth.frontier_sql_backend_pool_size,
						std::num::NonZeroU32::new(eth.frontier_sql_backend_num_ops_timeout),
						overrides.clone()
					)
				)
				.unwrap_or_else(|err| panic!("failed creating sql backend: {:?}", err));
			FrontierBackend::Sql(backend)
		}
	};
	let import_setup = (block_import, grandpa_link, babe_link);

	let statement_store = sc_statement_store::Store
		::new_shared(
			&config.data_path,
			Default::default(),
			client.clone(),
			config.prometheus_registry(),
			&task_manager.spawn_handle()
		)
		.map_err(|e| ServiceError::Other(format!("Statement store error: {:?}", e)))?;
	
	Ok(sc_service::PartialComponents {
		client,
		backend,
		task_manager,
		keystore_container,
		select_chain,
		import_queue,
		transaction_pool,
		other: (import_setup, telemetry, statement_store,babe_worker_handle, frontier_backend.into()),
	})
}

fn spawn_frontier_tasks(
	task_manager: &TaskManager,
	client: Arc<FullClient>,
	backend: Arc<FullBackend>,
	frontier_backend: FrontierBackend<Block>,
	filter_pool: Option<FilterPool>,
	overrides: Arc<OverrideHandle<Block>>,
	fee_history_cache: FeeHistoryCache,
	fee_history_cache_limit: FeeHistoryCacheLimit,
	sync: Arc<SyncingService<Block>>,
	pubsub_notification_sinks: Arc<fc_mapping_sync::EthereumBlockNotificationSinks<fc_mapping_sync::EthereumBlockNotification<Block>>>
) {
	// Spawn main mapping sync worker background task.
	match frontier_backend {
		fc_db::Backend::KeyValue(b) => {
			task_manager.spawn_essential_handle().spawn(
				"frontier-mapping-sync-worker",
				None,
				fc_mapping_sync::kv::MappingSyncWorker
					::new(
						client.import_notification_stream(),
						Duration::new(6, 0),
						client.clone(),
						backend,

						overrides.clone(),
						Arc::new(b),
						//Arc<FrontierBackend<Block>>,
						3,
						0,
						fc_mapping_sync::SyncStrategy::Normal,
						sync,
						pubsub_notification_sinks
					)
					.for_each(|()| future::ready(()))
			);
		}
		fc_db::Backend::Sql(b) => {
			task_manager.spawn_essential_handle().spawn_blocking(
				"frontier-mapping-sync-worker",
				None,
				fc_mapping_sync::sql::SyncWorker::run(
					client.clone(),
					backend,
					Arc::new(b),
					client.import_notification_stream(),
					fc_mapping_sync::sql::SyncWorkerConfig {
						read_notification_timeout: Duration::from_secs(10),
						check_indexed_blocks_interval: Duration::from_secs(60),
					},
					fc_mapping_sync::SyncStrategy::Parachain,
					sync,
					pubsub_notification_sinks
				)
			);
		}
	}

	// Spawn Frontier EthFilterApi maintenance task.
	if let Some(filter_pool) = filter_pool {
		// Each filter is allowed to stay in the pool for 100 blocks.
		const FILTER_RETAIN_THRESHOLD: u64 = 100;
		task_manager
			.spawn_essential_handle()
			.spawn(
				"frontier-filter-pool",
				Some("frontier"),
				EthTask::filter_pool_task(client.clone(), filter_pool, FILTER_RETAIN_THRESHOLD)
			);
	}
	let overrides = crate::rpc::overrides_handle(client.clone());

	// Spawn Frontier FeeHistory cache maintenance task.
	task_manager
		.spawn_essential_handle()
		.spawn(
			"frontier-fee-history",
			Some("frontier"),
			EthTask::fee_history_task(client, overrides, fee_history_cache, fee_history_cache_limit)
		);
}

/// Result of [`new_full_base`].
pub struct NewFullBase {
	/// The task manager of the node.
	pub task_manager: TaskManager,
	/// The client instance of the node.
	pub client: Arc<FullClient>,
	/// The networking service of the node.
	pub network: Arc<NetworkService<Block, <Block as BlockT>::Hash>>,
	/// The syncing service of the node.
	pub sync: Arc<SyncingService<Block>>,
	/// The transaction pool of the node.
	pub transaction_pool: Arc<TransactionPool>,
	/// The rpc handlers of the node.
	pub rpc_handlers: RpcHandlers,
}

/// Creates a full service from the configuration.
pub fn new_full_base(
	config: Configuration,
	disable_hardware_benchmarks: bool,
	with_startup_data: impl FnOnce(
		&sc_consensus_babe::BabeBlockImport<Block, FullClient, FullGrandpaBlockImport>,
		&sc_consensus_babe::BabeLink<Block>
	)
) -> Result<NewFullBase, ServiceError> {
	let hwbench = (!disable_hardware_benchmarks)
		.then_some(
			config.database.path().map(|database_path| {
				let _ = std::fs::create_dir_all(&database_path);
				sc_sysinfo::gather_hwbench(Some(database_path))
			})
		)
		.flatten();

	let sc_service::PartialComponents {
		client,
		backend,
		mut task_manager,
		import_queue,
		keystore_container,
		select_chain,
		transaction_pool,
		other: (import_setup, mut telemetry, statement_store, babe_worker_handle, frontier_backend),
	} = new_partial(&config)?;

	let statement_store_clone = statement_store.clone();

	let auth_disc_publish_non_global_ips = config.network.allow_non_globals_in_dht;
	let mut net_config = sc_network::config::FullNetworkConfiguration::new(&config.network);

	let grandpa_protocol_name = grandpa::protocol_standard_name(
		&client.block_hash(0).ok().flatten().expect("Genesis block exists; qed"),
		&config.chain_spec
	);
	net_config.add_notification_protocol(
		grandpa::grandpa_peers_set_config(grandpa_protocol_name.clone())
	);

	let statement_handler_proto = sc_network_statement::StatementHandlerPrototype::new(
		client.block_hash((0u32).into()).ok().flatten().expect("Genesis block exists; qed"),
		config.chain_spec.fork_id()
	);
	net_config.add_notification_protocol(statement_handler_proto.set_config());

	let warp_sync = Arc::new(
		grandpa::warp_proof::NetworkProvider::new(
			backend.clone(),
			import_setup.1.shared_authority_set().clone(),
			Vec::default()
		)
	);

	let (network, system_rpc_tx, tx_handler_controller, network_starter, sync_service) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			net_config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			block_announce_validator_builder: None,
			warp_sync_params: Some(WarpSyncParams::WithProvider(warp_sync.clone())),
		})?;
	let service = sync_service.clone();
	if config.offchain_worker.enabled {
		sc_service::build_offchain_workers(
			&config,
			task_manager.spawn_handle(),
			client.clone(),
			network.clone()
		);
	}

	let role = config.role.clone();
	let force_authoring = config.force_authoring;
	let backoff_authoring_blocks = Some(
		sc_consensus_slots::BackoffAuthoringOnFinalizedHeadLagging::default()
	);
	let name = config.network.node_name.clone();
	let enable_grandpa = !config.disable_grandpa;
	let prometheus_registry = config.prometheus_registry().cloned();

	let overrides = crate::rpc::overrides_handle(client.clone());
	let block_data_cache = Arc::new(
		fc_rpc::EthBlockDataCacheTask::new(
			task_manager.spawn_handle(),
			overrides.clone(),
			50,
			50,
			prometheus_registry.clone()
		)
	);

	let subscription_task_executor = Arc::new(task_manager.spawn_handle());
	let (_, grandpa_link, babe_link) = &import_setup;
	let justification_stream = grandpa_link.justification_stream();
	let shared_authority_set = grandpa_link.shared_authority_set().clone();
	let shared_voter_state = grandpa::SharedVoterState::empty();

	let finality_proof_provider = grandpa::FinalityProofProvider::new_for_service(
		backend.clone(),

		Some(shared_authority_set.clone())
	);

	let client = client.clone();
	// let pool = transaction_pool.clone();
	let select_chain = select_chain.clone();
	let keystore = keystore_container.keystore();
	let _chain_spec = config.chain_spec.cloned_box();
	let filter_pool: Option<FilterPool> = Some(Arc::new(Mutex::new(BTreeMap::new())));
	let fee_history_cache: FeeHistoryCache = Arc::new(Mutex::new(BTreeMap::new()));
	let fee_history_cache_limit: FeeHistoryCacheLimit = 1000;
	let execute_gas_limit_multiplier = 1000;
	let rpc_backend = backend.clone();
	let pubsub_notification_sinks: fc_mapping_sync::EthereumBlockNotificationSinks<fc_mapping_sync::EthereumBlockNotification<Block>> = Default::default();
	let pubsub_notification_sinks = Arc::new(pubsub_notification_sinks);

	let (grandpa_block_import, grandpa_link) = grandpa::block_import(
		client.clone(),
		&(client.clone() as Arc<_>),
		select_chain.clone(),
		telemetry.as_ref().map(|x| x.handle())
	)?;
	// let justification_import = grandpa_block_import.clone();

	let (block_import, babe_link) = sc_consensus_babe::block_import(
		sc_consensus_babe::configuration(&*client)?,
		grandpa_block_import,
		client.clone()
	)?;
	let slot_duration = babe_link.config().slot_duration();


	let rpc_extensions_builder = {
		let is_authority = false;
		let enable_dev_signer = false;
		let max_past_logs = 10000;
		let chain_spec = config.chain_spec.cloned_box();
		let client = client.clone();

		let pool = transaction_pool.clone();
		let network = network.clone();
		let select_chain = select_chain.clone();
		let voter_state = shared_voter_state.clone();

		let pubsub_notification_sinks = pubsub_notification_sinks.clone();

		let frontier_backend = frontier_backend.clone();
		let fee_history_cache = fee_history_cache.clone();
		let fee_history_cache_limit = fee_history_cache_limit.clone();
		let execute_gas_limit_multiplier = execute_gas_limit_multiplier.clone();
		let overrides = overrides.clone();
		let filter_pool = filter_pool.clone();

		Box::new(move |deny_unsafe, subscription_executor| {
			let deps = crate::rpc::FullDeps {
				client: client.clone(),
				pool: pool.clone(),
				graph: pool.pool().clone(),
				select_chain: select_chain.clone(),
				chain_spec: chain_spec.cloned_box(),
				deny_unsafe,
				sync: service.clone(),

				babe: crate::rpc::BabeDeps {
					keystore: keystore.clone(),
					babe_worker_handle: babe_worker_handle.clone(),
				},
				grandpa: crate::rpc::GrandpaDeps {
					shared_voter_state: voter_state.clone(),
					shared_authority_set: shared_authority_set.clone(),
					justification_stream: justification_stream.clone(),
					subscription_executor,
					finality_provider: finality_proof_provider.clone(),
				},
				statement_store: statement_store.clone(),
				is_authority,
				enable_dev_signer,
				overrides: overrides.clone(),
				block_data_cache: block_data_cache.clone(),
				network: network.clone(),
				filter_pool: filter_pool.clone(),
				backend: match frontier_backend.clone() {
					fc_db::Backend::KeyValue(b) => Arc::new(b),
					fc_db::Backend::Sql(b) => Arc::new(b),
				},
				max_past_logs,
				fee_history_cache: fee_history_cache.clone(),
				fee_history_cache_limit: fee_history_cache_limit.clone(),
				execute_gas_limit_multiplier: execute_gas_limit_multiplier.clone(),
				forced_parent_hashes: None,
			};

			crate::rpc
				::create_full(
					deps,
					subscription_task_executor.clone(),
					pubsub_notification_sinks.clone(),
					rpc_backend.clone()
				)
				.map_err(Into::into)
		})
	};

	let backend = backend.clone();
	let backends = backend.clone();
	let rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		config,
		backend,
		client: client.clone(),
		keystore: keystore_container.keystore(),
		network: network.clone(),
		// rpc_builder: Box::new(rpc_builder),
		rpc_builder: rpc_extensions_builder,
		transaction_pool: transaction_pool.clone(),
		task_manager: &mut task_manager,
		system_rpc_tx,
		tx_handler_controller,
		sync_service: sync_service.clone(),
		telemetry: telemetry.as_mut(),
	})?;

	let fee_history_cache: FeeHistoryCache = Arc::new(Mutex::new(BTreeMap::new()));
	let fee_history_cache_limit: FeeHistoryCacheLimit = 1000;
	let filter_pool: Option<FilterPool> = Some(Arc::new(Mutex::new(BTreeMap::new())));
	// let frontier_backend =
	// Arc::new(FrontierBackend::open(client.clone(),&config.database, &db_config_dir(config))?);
	spawn_frontier_tasks(
		&task_manager,
		client.clone(),
		backends,
		frontier_backend.into(),
		filter_pool,
		overrides.clone(),
		fee_history_cache,
		fee_history_cache_limit,
		sync_service.clone(),
		pubsub_notification_sinks
	);

	if let Some(hwbench) = hwbench {
		sc_sysinfo::print_hwbench(&hwbench);
		if !SUBSTRATE_REFERENCE_HARDWARE.check_hardware(&hwbench) && role.is_authority() {
			log::warn!(
				"⚠️  The hardware does not meet the minimal requirements for role 'Authority'."
			);
		}

		if let Some(ref mut telemetry) = telemetry {
			let telemetry_handle = telemetry.handle();
			task_manager
				.spawn_handle()
				.spawn(
					"telemetry_hwbench",
					None,
					sc_sysinfo::initialize_hwbench_telemetry(telemetry_handle, hwbench)
				);
		}
	}

	let (block_import, grandpa_link, babe_link) = import_setup;

	with_startup_data(&block_import, &babe_link);

	if let sc_service::config::Role::Authority { .. } = &role {
		let proposer = sc_basic_authorship::ProposerFactory::new(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool.clone(),
			prometheus_registry.as_ref(),
			telemetry.as_ref().map(|x| x.handle())
		);

		let client_clone = client.clone();

		let babe_config = sc_consensus_babe::BabeParams {
			keystore: keystore_container.keystore(),
			client: client.clone(),
			select_chain,
			env: proposer,
			block_import,
			sync_oracle: sync_service.clone(),
			justification_sync_link: sync_service.clone(),
			create_inherent_data_providers: move |parent, ()| {
				let client_clone = client_clone.clone();
				async move {
					let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

					let slot =
						sp_consensus_babe::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
							*timestamp,
							slot_duration
						);

					let storage_proof =
						sp_transaction_storage_proof::registration::new_data_provider(
							&*client_clone,
							&parent
						)?;

					Ok((slot, timestamp, storage_proof))
				}
			},
			force_authoring,
			backoff_authoring_blocks,
			babe_link,
			block_proposal_slot_portion: SlotProportion::new(0.5),
			max_block_proposal_slot_portion: None,
			telemetry: telemetry.as_ref().map(|x| x.handle()),
		};

		let babe = sc_consensus_babe::start_babe(babe_config)?;
		task_manager
			.spawn_essential_handle()
			.spawn_blocking("babe-proposer", Some("block-authoring"), babe);
	}

	// Spawn authority discovery module.
	if role.is_authority() {
		let authority_discovery_role = sc_authority_discovery::Role::PublishAndDiscover(
			keystore_container.keystore()
		);
		let dht_event_stream = network
			.event_stream("authority-discovery")
			.filter_map(|e| async move {
				match e {
					Event::Dht(e) => Some(e),
					_ => None,
				}
			});
		let (authority_discovery_worker, _service) =
			sc_authority_discovery::new_worker_and_service_with_config(
				sc_authority_discovery::WorkerConfig {
					publish_non_global_ips: auth_disc_publish_non_global_ips,
					..Default::default()
				},
				client.clone(),
				network.clone(),
				Box::pin(dht_event_stream),
				authority_discovery_role,
				prometheus_registry.clone()
			);

		task_manager
			.spawn_handle()
			.spawn(
				"authority-discovery-worker",
				Some("networking"),
				authority_discovery_worker.run()
			);
	}

	// if the node isn't actively participating in consensus then it doesn't
	// need a keystore, regardless of which protocol we use below.
	let keystore = if role.is_authority() { Some(keystore_container.keystore()) } else { None };

	let config = grandpa::Config {
		// FIXME #1578 make this available through chainspec
		gossip_duration: std::time::Duration::from_millis(333),
		justification_period: 512,
		name: Some(name),
		observer_enabled: false,
		keystore,
		local_role: role,
		telemetry: telemetry.as_ref().map(|x| x.handle()),
		protocol_name: grandpa_protocol_name,
	};

	if enable_grandpa {
		// start the full GRANDPA voter
		// NOTE: non-authorities could run the GRANDPA observer protocol, but at
		// this point the full voter should provide better guarantees of block
		// and vote data availability than the observer. The observer has not
		// been tested extensively yet and having most nodes in a network run it
		// could lead to finality stalls.
		let grandpa_config = grandpa::GrandpaParams {
			config,
			link: grandpa_link,
			network: network.clone(),
			sync: Arc::new(sync_service.clone()),
			telemetry: telemetry.as_ref().map(|x| x.handle()),
			voting_rule: grandpa::VotingRulesBuilder::default().build(),
			prometheus_registry: prometheus_registry.clone(),
			shared_voter_state,
		};

		// the GRANDPA voter task is considered infallible, i.e.
		// if it fails we take down the service with it.
		task_manager
			.spawn_essential_handle()
			.spawn_blocking("grandpa-voter", None, grandpa::run_grandpa_voter(grandpa_config)?);
	}

	// Spawn statement protocol worker
	let statement_protocol_executor = {
		let spawn_handle = task_manager.spawn_handle();
		Box::new(move |fut| {
			spawn_handle.spawn("network-statement-validator", Some("networking"), fut);
		})
	};

	let statement_handler = statement_handler_proto.build(
		network.clone(),
		sync_service.clone(),
		statement_store_clone.clone(),
		prometheus_registry.as_ref(),
		statement_protocol_executor
	)?;
	task_manager
		.spawn_handle()
		.spawn("network-statement-handler", Some("networking"), statement_handler.run());

	network_starter.start_network();
	Ok(NewFullBase {
		task_manager,
		client,
		network,
		sync: sync_service,
		transaction_pool,
		rpc_handlers,
	})
}

/// Builds a new service for a full client.
pub fn new_full(config: Configuration, cli: Cli) -> Result<TaskManager, ServiceError> {
	let database_source = config.database.clone();
	let task_manager = new_full_base(config, cli.no_hardware_benchmarks, |_, _| ()).map(
		|NewFullBase { task_manager, .. }| task_manager
	)?;

	sc_storage_monitor::StorageMonitorService
		::try_spawn(cli.storage_monitor, database_source, &task_manager.spawn_essential_handle())
		.map_err(|e| ServiceError::Application(e.into()))?;

	Ok(task_manager)
}

#[cfg(test)]
mod tests {
	use crate::service::{ new_full_base, NewFullBase };
	use codec::Encode;
	use node_5ire_runtime::{
		constants::{ currency::CENTS, time::SLOT_DURATION },
		Address,
		BalancesCall,
		RuntimeCall,
		UncheckedExtrinsic,
	};
	use node_primitives::{ Block, DigestItem, Signature };
	use sc_client_api::BlockBackend;
	use sc_consensus::{ BlockImport, BlockImportParams, ForkChoiceStrategy };
	use sc_consensus_babe::{ BabeIntermediate, CompatibleDigestItem, INTERMEDIATE_KEY };
	use sc_consensus_epochs::descendent_query;
	use sc_keystore::LocalKeystore;
	use sc_service_test::TestNetNode;
	use sc_transaction_pool_api::{ ChainEvent, MaintainedTransactionPool };
	use sp_consensus::{ BlockOrigin, Environment, Proposer };
	use sp_core::crypto::Pair;
	use sp_inherents::InherentDataProvider;
	use sp_keyring::AccountKeyring;
	use sp_keystore::KeystorePtr;
	use sp_runtime::{
		generic::{ Digest, Era, SignedPayload },
		key_types::BABE,
		traits::{ Block as BlockT, Header as HeaderT, IdentifyAccount, Verify },
		RuntimeAppPublic,
	};
	use sp_timestamp;
	use std::sync::Arc;

	type AccountPublic = <Signature as Verify>::Signer;

	#[test]
	// It is "ignored", but the node-cli ignored tests are running on the CI.
	// This can be run locally with `cargo test --release -p node-cli test_sync -- --ignored`.
	#[ignore]
	fn test_sync() {
		sp_tracing::try_init_simple();

		let keystore_path = tempfile::tempdir().expect("Creates keystore path");
		let keystore: KeystorePtr = LocalKeystore::open(keystore_path.path(), None)
			.expect("Creates keystore")
			.into();
		let alice: sp_consensus_babe::AuthorityId = keystore
			.sr25519_generate_new(BABE, Some("//Alice"))
			.expect("Creates authority pair")
			.into();

		let chain_spec = crate::chain_spec::tests::integration_test_config_with_single_authority();

		// For the block factory
		let mut slot = 1u64;

		// For the extrinsics factory
		let bob = Arc::new(AccountKeyring::Bob.pair());
		let charlie = Arc::new(AccountKeyring::Charlie.pair());
		let mut index = 0;

		sc_service_test::sync(
			chain_spec,
			|config| {
				let mut setup_handles = None;
				let NewFullBase { task_manager, client, network, sync, transaction_pool, .. } =
					new_full_base(
						config,
						false,
						|
							block_import: &sc_consensus_babe::BabeBlockImport<Block, _, _>,
							babe_link: &sc_consensus_babe::BabeLink<Block>
						| {
							setup_handles = Some((block_import.clone(), babe_link.clone()));
						}
					)?;

				let node = sc_service_test::TestNetComponents::new(
					task_manager,
					client,
					network,
					sync,
					transaction_pool
				);
				Ok((node, setup_handles.unwrap()))
			},
			|service, &mut (ref mut block_import, ref babe_link)| {
				let parent_hash = service.client().chain_info().best_hash;
				let parent_header = service.client().header(parent_hash).unwrap().unwrap();
				let parent_number = *parent_header.number();

				futures::executor::block_on(
					service.transaction_pool().maintain(ChainEvent::NewBestBlock {
						hash: parent_header.hash(),
						tree_route: None,
					})
				);

				let mut proposer_factory = sc_basic_authorship::ProposerFactory::new(
					service.spawn_handle(),
					service.client(),
					service.transaction_pool(),
					None,
					None
				);

				let mut digest = Digest::default();

				// even though there's only one authority some slots might be empty,
				// so we must keep trying the next slots until we can claim one.
				let (babe_pre_digest, epoch_descriptor) = loop {
					let epoch_descriptor = babe_link
						.epoch_changes()
						.shared_data()
						.epoch_descriptor_for_child_of(
							descendent_query(&*service.client()),
							&parent_hash,
							parent_number,
							slot.into()
						)
						.unwrap()
						.unwrap();

					let epoch = babe_link
						.epoch_changes()
						.shared_data()
						.epoch_data(&epoch_descriptor, |slot| {
							sc_consensus_babe::Epoch::genesis(babe_link.config(), slot)
						})
						.unwrap();

					if
						let Some(babe_pre_digest) = sc_consensus_babe::authorship
							::claim_slot(slot.into(), &epoch, &keystore)
							.map(|(digest, _)| digest)
					{
						break (babe_pre_digest, epoch_descriptor);
					}

					slot += 1;
				};

				let inherent_data = futures::executor
					::block_on(
						(
							sp_timestamp::InherentDataProvider::new(
								std::time::Duration::from_millis(SLOT_DURATION * slot).into()
							),
							sp_consensus_babe::inherents::InherentDataProvider::new(slot.into()),
						).create_inherent_data()
					)
					.expect("Creates inherent data");

				digest.push(<DigestItem as CompatibleDigestItem>::babe_pre_digest(babe_pre_digest));

				let new_block = futures::executor
					::block_on(async move {
						let proposer = proposer_factory.init(&parent_header).await;
						proposer
							.unwrap()
							.propose(
								inherent_data,
								digest,
								std::time::Duration::from_secs(1),
								None
							).await
					})
					.expect("Error making test block").block;

				let (new_header, new_body) = new_block.deconstruct();
				let pre_hash = new_header.hash();
				// sign the pre-sealed hash of the block and then
				// add it to a digest item.
				let to_sign = pre_hash.encode();
				let signature = keystore
					.sr25519_sign(sp_consensus_babe::AuthorityId::ID, alice.as_ref(), &to_sign)
					.unwrap()
					.unwrap();
				let item = <DigestItem as CompatibleDigestItem>::babe_seal(signature.into());
				slot += 1;

				let mut params = BlockImportParams::new(BlockOrigin::File, new_header);
				params.post_digests.push(item);
				params.body = Some(new_body);
				params.insert_intermediate(INTERMEDIATE_KEY, BabeIntermediate::<Block> {
					epoch_descriptor,
				});
				params.fork_choice = Some(ForkChoiceStrategy::LongestChain);

				futures::executor
					::block_on(block_import.import_block(params))
					.expect("error importing test block");
			},
			|service, _| {
				let amount = 5 * CENTS;
				let to: Address = AccountPublic::from(bob.public()).into_account().into();
				let from: Address = AccountPublic::from(charlie.public()).into_account().into();
				let genesis_hash = service.client().block_hash(0).unwrap().unwrap();
				let best_hash = service.client().chain_info().best_hash;
				let (spec_version, transaction_version) = {
					let version = service.client().runtime_version_at(best_hash).unwrap();
					(version.spec_version, version.transaction_version)
				};
				let signer = charlie.clone();

				let function = RuntimeCall::Balances(BalancesCall::transfer_allow_death {
					dest: to.into(),
					value: amount,
				});

				let check_non_zero_sender = frame_system::CheckNonZeroSender::new();
				let check_spec_version = frame_system::CheckSpecVersion::new();
				let check_tx_version = frame_system::CheckTxVersion::new();
				let check_genesis = frame_system::CheckGenesis::new();
				let check_era = frame_system::CheckEra::from(Era::Immortal);
				let check_nonce = frame_system::CheckNonce::from(index);
				let check_weight = frame_system::CheckWeight::new();
				let tx_payment = pallet_asset_tx_payment::ChargeAssetTxPayment::from(0, None);
				let extra = (
					check_non_zero_sender,
					check_spec_version,
					check_tx_version,
					check_genesis,
					check_era,
					check_nonce,
					check_weight,
					tx_payment,
				);
				let raw_payload = SignedPayload::from_raw(function, extra, (
					(),
					spec_version,
					transaction_version,
					genesis_hash,
					genesis_hash,
					(),
					(),
					(),
				));
				let signature = raw_payload.using_encoded(|payload| signer.sign(payload));
				let (function, extra, _) = raw_payload.deconstruct();
				index += 1;
				UncheckedExtrinsic::new_signed(
					function,
					from.into(),
					signature.into(),
					extra
				).into()
			}
		);
	}

	#[test]
	#[ignore]
	fn test_consensus() {
		sp_tracing::try_init_simple();

		sc_service_test::consensus(
			crate::chain_spec::tests::integration_test_config_with_two_authorities(),
			|config| {
				let NewFullBase { task_manager, client, network, sync, transaction_pool, .. } =
					new_full_base(config, false, |_, _| ())?;
				Ok(
					sc_service_test::TestNetComponents::new(
						task_manager,
						client,
						network,
						sync,
						transaction_pool
					)
				)
			},
			vec!["//Alice".into(), "//Bob".into()]
		)
	}
}
