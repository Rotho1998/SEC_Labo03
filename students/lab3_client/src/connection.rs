use native_tls::TlsStream;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::error::Error;
use std::net::TcpStream;

pub struct Connection {
    stream: TlsStream<TcpStream>,
}

impl Connection {
    pub fn new(stream: TlsStream<TcpStream>) -> Connection {
        Connection { stream }
    }

    pub fn send<T>(&mut self, o: &T) -> Result<(), Box<dyn Error>>
        where
            T: Serialize,
    {
        Ok(bincode::serialize_into(&mut self.stream, &o)?)
    }

    pub fn receive<T>(&mut self) -> Result<T, Box<dyn Error>>
        where
            T: DeserializeOwned,
    {
        Ok(bincode::deserialize_from(&mut self.stream)?)
    }
}
