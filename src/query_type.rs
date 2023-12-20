
/* == QueryType == */
/// Record type being queried, used for DNS question

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A, /// Alias: map name to IP
    NS, /// Name server: address of the DNS server for a domain
    CNAME, /// Canonical name: maps names to names
    MX, /// Main eXchange: the host of the email server for a domain
    AAAA, // /// IPv6 alias
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num)
        }
    }
}
