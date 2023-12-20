use crate::byte_packet_buffer::BytePacketBuffer;
use crate::result_code::ResultCode;


type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

/* == DnsHeader == */

/// Header with information on the packet

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // packet identifier, response packet must have the same id

    pub recursion_desired: bool, // set by the sender if the server should
    // attempt to resolve the query recursively
    pub truncate_message: bool, // set if message exceeds 512 bytes
    pub authoritative_answer: bool, // set if server that responds is authoritative
    pub opcode: u8, // tipically always 0
    pub response: bool, // 0 for queries, 1 for responses

    pub rescode: ResultCode, // set by server to indicate status of response
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool, // reserved
    pub recursion_available: bool, // set by the server to indicate whether
    // or not recursion is available

    // number of _ :
    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncate_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncate_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    /// Write a new Dns Header
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8) |
                ((self.truncate_message as u8) << 1) |
                ((self.authoritative_answer as u8) << 2) |
                ((self.opcode) << 3) |
                ((self.response as u8) << 7) as u8
        )?;

        buffer.write_u8(
            (self.rescode as u8) |
                ((self.checking_disabled as u8) << 4) |
                ((self.authed_data as u8) << 5) |
                ((self.z as u8) << 6) |
                ((self.recursion_available as u8) << 7)
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

