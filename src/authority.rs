use std::net::Ipv4Addr;
use std::str::from_utf8;
use std::sync::Arc;

use trust_dns_server::authority::{
    AuthLookup, AuthorityObject, LookupError, LookupObject, LookupOptions, LookupRecords,
    MessageRequest, UpdateResult, ZoneType,
};
use trust_dns_server::proto::op::ResponseCode;
use trust_dns_server::proto::rr::{IntoName, LowerName, RData, RecordSet, RecordType};
use trust_dns_server::proto::rr::rdata::A;
use trust_dns_server::server::RequestInfo;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DynamicAuthority {
    root: LowerName,
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("ProtoError: {0}")]
    Proto(#[from] trust_dns_server::proto::error::ProtoError),
    #[error("Ip not found")]
    IpNotFound,
    #[error("Unable to parse")]
    UnableToParse,
    #[error("Utf8Error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("ParseIntError: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
}

impl DynamicAuthority {
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub fn new(root: LowerName) -> Self {
        DynamicAuthority { root }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn parse_ipv4_by_split(parts: &[&str]) -> Result<Ipv4Addr, Error> {
        if parts.len() < 4 {
            return Err(Error::UnableToParse);
        }

        let len = parts.len();
        let ip = Ipv4Addr::new(
            parts[len - 4].parse()?,
            parts[len - 3].parse()?,
            parts[len - 2].parse()?,
            parts[len - 1].parse()?,
        );

        Ok(ip)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn parse_ipv4_from_name(lower_name: &LowerName) -> Result<Ipv4Addr, Error> {
        let name = lower_name.into_name()?;

        let labels = {
            let mut labels = name.into_iter().rev().collect::<Vec<_>>();
            if labels.len() < 3 {
                log::error!("Invalid name: {:?}", name);
                return Err(Error::IpNotFound);
            }
            labels.drain(0..2); // remove the first two labels which is the root domain
            labels
        };

        #[cfg(feature = "tracing")]
        tracing::debug!("Labels: {:?}", labels);

        if labels.len() >= 4 {
            let mut parts = Vec::new();
            for key in labels.iter().rev() {
                parts.push(from_utf8(key)?);
            }

            if let Ok(ip) = Self::parse_ipv4_by_split(&parts).map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Unable to parse: {:?}", e);
                e
            }) {
                return Ok(ip);
            }
        }

        // check if the third label is an ip address
        {
            let s = from_utf8(labels[0])?;

            // match xxx-1-2-3-4
            if let Ok(ip) = Self::parse_ipv4_by_split(&s.split('-').collect::<Vec<_>>()) {
                return Ok(ip);
            }

            // match 4-3-2-1-xxx
            if let Ok(ip) = Self::parse_ipv4_by_split(&s.split('-').rev().collect::<Vec<_>>()) {
                return Ok(ip);
            }

            if s == "local" || s == "localhost" {
                return Ok(Ipv4Addr::new(127, 0, 0, 1));
            }
        }

        Err(Error::IpNotFound)
    }
}

#[async_trait::async_trait]
impl AuthorityObject for DynamicAuthority {
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn box_clone(&self) -> Box<dyn AuthorityObject> {
        Box::new(self.clone())
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn is_axfr_allowed(&self) -> bool {
        false
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
        Err(ResponseCode::NotImp)
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    fn origin(&self) -> &LowerName {
        &self.root
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        match rtype {
            RecordType::A => {
                if let Ok(ip) = Self::parse_ipv4_from_name(name).map_err(|e| {
                    #[cfg(feature = "tracing")]
                    tracing::error!("Unable to parse: {:?}", e);
                    e
                }) {
                    let mut record_set =
                        RecordSet::new(&name.into_name().unwrap(), RecordType::A, 300);
                    record_set.new_record(&RData::A(A::from(ip)));
                    return Ok(Box::new(AuthLookup::answers(
                        LookupRecords::new(lookup_options, Arc::new(record_set)),
                        None,
                    )));
                }
            }
            _ => {
                log::debug!("Unsupported record type: {:?}", rtype)
            }
        }

        Err(LookupError::ResponseCode(ResponseCode::NXDomain))
    }

    async fn search(
        &self,
        request: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        let name = request.query.name();
        let rtype = request.query.query_type();

        self.lookup(name, rtype, lookup_options).await
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn get_nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> Result<Box<dyn LookupObject>, LookupError> {
        todo!()
    }
}
