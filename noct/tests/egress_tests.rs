use std::net::Ipv4Addr;

use aya::{Ebpf, TestRun, TestRunOptions, maps::PerfEventArray, programs::CgroupSkb};
use etherparse::{Ethernet2Header, PacketBuilder, PacketBuilderStep};
use tokio::sync::mpsc;

const IP_PROTO_UDP: u8 = 17;
const IP_PROTO_TCP: u8 = 6;

fn build_l2_packet() -> PacketBuilderStep<Ethernet2Header> {
    PacketBuilder::ethernet2(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
    )
}

#[tokio::test]
async fn test_single_packet_udp_no_payload() -> anyhow::Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/noct"
    )))?;

    {
        let egress_program: &mut CgroupSkb = ebpf.program_mut("egress").unwrap().try_into()?;
        egress_program.load()?;
    }

    let egress_stats_map = PerfEventArray::try_from(ebpf.take_map("TX_STATS").unwrap())?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    noct::read_event_array(egress_stats_map, tx)?;

    let src_addr = Ipv4Addr::from_octets([192, 168, 1, 1]);
    let dst_addr = Ipv4Addr::from_octets([192, 168, 1, 2]);
    let src_port = 12000;
    let dst_port = 34000;
    let builder = build_l2_packet()
        .ipv4(src_addr.octets(), dst_addr.octets(), 10)
        .udp(src_port, dst_port);

    let tot_len = builder.size(0);
    let mut packet = Vec::<u8>::with_capacity(tot_len);
    builder.write(&mut packet, &[])?;

    let opts = TestRunOptions {
        data_in: Some(&packet),
        repeat: 1,
        ..Default::default()
    };

    let result = {
        let egress_program: &mut CgroupSkb = ebpf.program_mut("egress").unwrap().try_into()?;

        egress_program.test_run(opts)?
    };
    assert_eq!(result.return_value, 1);

    let stats = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("no event received"))?;
    rx.close();

    assert_eq!(stats.src_addr, src_addr);
    assert_eq!(stats.dst_addr, dst_addr);
    assert_eq!(stats.src_port, src_port);
    assert_eq!(stats.dst_port, dst_port);
    assert_eq!(stats.protocol, IP_PROTO_UDP);
    assert_eq!(stats.payload_len, 0);
    assert_eq!(usize::from(stats.pkt_len), tot_len - Ethernet2Header::LEN);

    Ok(())
}

#[tokio::test]
async fn test_single_packet_udp_with_payload() -> anyhow::Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/noct"
    )))?;

    {
        let egress_program: &mut CgroupSkb = ebpf.program_mut("egress").unwrap().try_into()?;
        egress_program.load()?;
    }

    let egress_stats_map = PerfEventArray::try_from(ebpf.take_map("TX_STATS").unwrap())?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    noct::read_event_array(egress_stats_map, tx)?;

    let src_addr = Ipv4Addr::from_octets([192, 168, 1, 1]);
    let dst_addr = Ipv4Addr::from_octets([192, 168, 1, 2]);
    let src_port = 12000;
    let dst_port = 34000;
    let builder = build_l2_packet()
        .ipv4(src_addr.octets(), dst_addr.octets(), 10)
        .udp(src_port, dst_port);
    let payload = b"foobar";

    let tot_len = builder.size(payload.len());
    let mut packet = Vec::<u8>::with_capacity(tot_len);
    builder.write(&mut packet, payload)?;

    let opts = TestRunOptions {
        data_in: Some(&packet),
        repeat: 1,
        ..Default::default()
    };

    let result = {
        let egress_program: &mut CgroupSkb = ebpf.program_mut("egress").unwrap().try_into()?;

        egress_program.test_run(opts)?
    };
    assert_eq!(result.return_value, 1);

    let stats = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("no event received"))?;
    rx.close();

    assert_eq!(stats.src_addr, src_addr);
    assert_eq!(stats.dst_addr, dst_addr);
    assert_eq!(stats.src_port, src_port);
    assert_eq!(stats.dst_port, dst_port);
    assert_eq!(stats.protocol, IP_PROTO_UDP);
    assert_eq!(usize::from(stats.payload_len), payload.len());
    assert_eq!(usize::from(stats.pkt_len), tot_len - Ethernet2Header::LEN);

    Ok(())
}

#[tokio::test]
async fn test_single_packet_tcp_no_payload() -> anyhow::Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/noct"
    )))?;

    {
        let egress_program: &mut CgroupSkb = ebpf.program_mut("egress").unwrap().try_into()?;
        egress_program.load()?;
    }

    let egress_stats_map = PerfEventArray::try_from(ebpf.take_map("TX_STATS").unwrap())?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    noct::read_event_array(egress_stats_map, tx)?;

    let src_addr = Ipv4Addr::from_octets([192, 168, 1, 1]);
    let dst_addr = Ipv4Addr::from_octets([192, 168, 1, 2]);
    let src_port = 12000;
    let dst_port = 34000;
    let builder = build_l2_packet()
        .ipv4(src_addr.octets(), dst_addr.octets(), 10)
        .tcp(src_port, dst_port, 12345, 64240);

    let tot_len = builder.size(0);
    let mut packet = Vec::<u8>::with_capacity(tot_len);
    builder.write(&mut packet, &[])?;

    let opts = TestRunOptions {
        data_in: Some(&packet),
        repeat: 1,
        ..Default::default()
    };

    let result = {
        let egress_program: &mut CgroupSkb = ebpf.program_mut("egress").unwrap().try_into()?;

        egress_program.test_run(opts)?
    };
    assert_eq!(result.return_value, 1);

    let stats = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("no event received"))?;
    rx.close();

    assert_eq!(stats.src_addr, src_addr);
    assert_eq!(stats.dst_addr, dst_addr);
    assert_eq!(stats.src_port, src_port);
    assert_eq!(stats.dst_port, dst_port);
    assert_eq!(stats.protocol, IP_PROTO_TCP);
    assert_eq!(stats.payload_len, 0);
    assert_eq!(usize::from(stats.pkt_len), tot_len - Ethernet2Header::LEN);

    Ok(())
}

#[tokio::test]
async fn test_single_packet_tcp_with_payload() -> anyhow::Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/noct"
    )))?;

    {
        let egress_program: &mut CgroupSkb = ebpf.program_mut("egress").unwrap().try_into()?;
        egress_program.load()?;
    }

    let egress_stats_map = PerfEventArray::try_from(ebpf.take_map("TX_STATS").unwrap())?;
    let (tx, mut rx) = mpsc::unbounded_channel();
    noct::read_event_array(egress_stats_map, tx)?;

    let src_addr = Ipv4Addr::from_octets([192, 168, 1, 1]);
    let dst_addr = Ipv4Addr::from_octets([192, 168, 1, 2]);
    let src_port = 12000;
    let dst_port = 34000;
    let builder = build_l2_packet()
        .ipv4(src_addr.octets(), dst_addr.octets(), 10)
        .tcp(src_port, dst_port, 12345, 62310);
    let payload = b"foobar";

    let tot_len = builder.size(payload.len());
    let mut packet = Vec::<u8>::with_capacity(tot_len);
    builder.write(&mut packet, payload)?;

    let opts = TestRunOptions {
        data_in: Some(&packet),
        repeat: 1,
        ..Default::default()
    };

    let result = {
        let egress_program: &mut CgroupSkb = ebpf.program_mut("egress").unwrap().try_into()?;

        egress_program.test_run(opts)?
    };
    assert_eq!(result.return_value, 1);

    let stats = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("no event received"))?;
    rx.close();

    assert_eq!(stats.src_addr, src_addr);
    assert_eq!(stats.dst_addr, dst_addr);
    assert_eq!(stats.src_port, src_port);
    assert_eq!(stats.dst_port, dst_port);
    assert_eq!(stats.protocol, IP_PROTO_TCP);
    assert_eq!(usize::from(stats.payload_len), payload.len());
    assert_eq!(usize::from(stats.pkt_len), tot_len - Ethernet2Header::LEN);

    Ok(())
}
