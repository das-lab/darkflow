use crate::{flows::util::FlowExpireCause, packet_features::PacketFeatures};
use super::util::{FlowFeature};

#[derive(Clone)]
pub struct PacketSequence {
    dirs: Vec<i32>,        // Direction (/ -)
    lens: Vec<i32>,        // With direction (/ -)
    timestamps: Vec<i64>,  // Relative time us
    first_ts: Option<i64>,
}

impl PacketSequence {
    pub fn new() -> Self {
        Self {
            dirs: Vec::new(),
            lens: Vec::new(),
            timestamps: Vec::new(),
            first_ts: None,
        }
    }

    fn vec_to_string<T: ToString>(v: &[T]) -> String {
        let inner = v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!("[{}]", inner)
    }
}

impl FlowFeature for PacketSequence {
    fn update(&mut self, packet: &PacketFeatures, fwd: bool, _last_ts: i64) {
        let ts = packet.timestamp_us;

        // Initialize the time of the first package
        let first = self.first_ts.get_or_insert(ts);

        self.dirs.push(if fwd { 1 } else { -1 });
        // Bag length (with direction)
        let len = packet.length as i32;
        let signed_len = if fwd { len } else { -len };
        self.lens.push(signed_len);

        // Relative time
        self.timestamps.push(ts - *first);
    }

    fn close(&mut self, _timestamp: i64, _cause: FlowExpireCause) {}

    fn dump(&self) -> String {
        format!(
            "{},{},{},{}",
            Self::vec_to_string(&self.dirs),
            // Pure packet length sequence
            Self::vec_to_string(
                &self.lens.iter().map(|v| v.abs()).collect::<Vec<_>>()
            ),
            // Long sequence of upstream and downstream packets
            Self::vec_to_string(&self.lens),
            // Time series
            Self::vec_to_string(&self.timestamps),
        )
    }

    fn headers() -> String
    where
        Self: Sized,
    {
        "pkt_dir_seq,pkt_len_seq,pkt_len_dir_seq,pkt_usec_seq".to_string()
    }
}
