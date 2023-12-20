use crate::byte_packet_buffer::BytePacketBuffer;
use crate::query_type::QueryType;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;
/* == DnsQuestion == */

/// Query name (domain) and record type

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name,
            qtype
        }
    }
    // Read the qname from the packet
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _ = buffer.read_u16()?;

        Ok(())
    }

    /// Write the qname to the buffer
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?; // write name

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?; // write type number
        buffer.write_u16(1)?; // ?

        Ok(())
    }

}
