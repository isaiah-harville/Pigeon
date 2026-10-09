#[derive(Clone)]
pub struct ConnectionState {
    service: Service,
    coordinator: coordinator::Service,
    push: Arc<PushRegistry>,
    connection_ids: Arc<AtomicU64>,
    admission_difficulty: u8,
    socket_slots: Arc<Semaphore>,
    socket_admission: SocketAdmission,
    trusted_proxy_ip: Option<IpAddr>,
}

impl FromRef<AppState> for ConnectionState {
    fn from_ref(state: &AppState) -> Self {
        Self {
            service: state.group.clone(),
            coordinator: state.coordinator.clone(),
            push: state.push.clone(),
            connection_ids: state.connection_ids.clone(),
            admission_difficulty: state.group_admission_difficulty,
            socket_slots: state.socket_slots.clone(),
            socket_admission: state.socket_admission.clone(),
            trusted_proxy_ip: state.trusted_proxy_ip,
        }
    }
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<ConnectionState>,
    connection: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Ok(slot) = state.socket_slots.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let peer_ip = client_ip(
        connection.map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |value| value.0.ip()),
        &headers,
        state.trusted_proxy_ip,
    );
    let Some(ip_slot) = state.socket_admission.acquire(peer_ip) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(MAX_GROUP_FRAME_BYTES)
        .on_upgrade(move |socket| async move {
            let _slot = slot;
            let _ip_slot = ip_slot;
            handle_socket(socket, state).await;
        })
        .into_response()
}
