
use crate::byte_packet_buffer::BytePacketBuffer;
use crate::dns_header::DnsHeader;
use crate::dns_question::DnsQuestion;
use crate::dns_record::DnsRecord;
use crate::query_type::QueryType;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;
/* == DnsPacket == */

/// Representation of the whole DNS packet

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut res = DnsPacket::new();
        res.header.read(buffer)?;

        for _ in 0..res.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            res.questions.push(question);
        }
        for _ in 0..res.header.answers {
            let rec = DnsRecord::read(buffer)?;
            res.answers.push(rec);
        }
        for _ in 0..res.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            res.authorities.push(rec);
        }
        for _ in 0..res.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            res.resources.push(rec);
        }

        Ok(res)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for q in &self.questions {
            q.write(buffer)?;
        }
        for a in &self.answers {
            a.write(buffer)?;
        }
        for a in &self.authorities {
            a.write(buffer)?;
        }
        for r in &self.resources {
            r.write(buffer)?;
        }

        Ok(())
    }
}
