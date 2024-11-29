use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use russh::{
    client,
    keys::key,
    server::{self, Server as _},
    Channel,
};
use russh_keys::key::{KeyPair, PublicKey};
use tokio::{sync::RwLock, time::sleep};

#[tokio::main]
async fn main() {
    env_logger::init();
    let client_key = Arc::new(russh_keys::key::KeyPair::generate_ed25519());
    let tcp_handle: Arc<RwLock<Option<russh::server::Handle>>> = Default::default();

    // Create server for remote port forwarding
    let server_config = Arc::new(server::Config {
        keys: vec![russh_keys::key::KeyPair::generate_ed25519()],
        ..Default::default()
    });
    let mut server = Server {
        key: Arc::clone(&client_key),
        tcp_handle: Arc::clone(&tcp_handle),
    };
    tokio::spawn(async move {
        server
            .run_on_address(server_config, "127.0.0.1:42222")
            .await
            .unwrap();
    });

    // Create client with tcpip_forward
    let mut session = client::connect(Default::default(), "127.0.0.1:42222", ClientHandler)
        .await
        .unwrap();
    if !session
        .authenticate_publickey("user", client_key)
        .await
        .unwrap()
    {
        panic!("Authentication failed.");
    }
    session
        .tcpip_forward("localhost", 1234)
        .await
        .expect("tcpip_forward failed");

    // Simulate incoming traffic
    let mut count = 0usize;
    let step = 500usize;
    loop {
        sleep(Duration::from_millis(500)).await;
        println!("Sending messages {} - {}...", count + 1, count + step);
        let lock = tcp_handle.read().await;
        let handle = lock.as_ref().unwrap();
        for _ in 0..step {
            let channel = handle
                .channel_open_forwarded_tcpip("foo", 12345, "bar", 23456)
                .await
                .unwrap();
            let mut _stream = channel.into_stream();
            // ... Do some stuff ...
        }
        count += step;
    }
}

struct ClientHandler;

#[async_trait]
impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        // Interacting with the channel isn't required to trigger the leak
        Ok(())
    }
}

struct Server {
    key: Arc<KeyPair>,
    tcp_handle: Arc<RwLock<Option<russh::server::Handle>>>,
}

impl server::Server for Server {
    type Handler = ServerHandler;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self::Handler {
        ServerHandler {
            key: self.key.clone_public_key().unwrap(),
            tcp_handle: Arc::clone(&self.tcp_handle),
        }
    }
}

struct ServerHandler {
    key: PublicKey,
    tcp_handle: Arc<RwLock<Option<russh::server::Handle>>>,
}

#[async_trait]
impl server::Handler for ServerHandler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        if public_key.fingerprint() == self.key.fingerprint() {
            Ok(server::Auth::Accept)
        } else {
            Ok(server::Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        *self.tcp_handle.write().await = Some(session.handle());
        Ok(true)
    }
}
