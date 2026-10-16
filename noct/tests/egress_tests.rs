use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, str::FromStr};

use aya::{Ebpf, TestRun, TestRunOptions, maps::PerfEventArray, programs::CgroupSkb};
use etherparse::{Ethernet2Header, PacketBuilder, PacketBuilderStep};
use noct_db::IpProto;
use tokio::sync::{broadcast, mpsc};

fn build_l2_packet() -> PacketBuilderStep<Ethernet2Header> {
    PacketBuilder::ethernet2(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
    )
}

#[tokio::test]
async fn test_graceful_shutdown() -> anyhow::Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/noct"
    )))?;

    let egress_program: &mut CgroupSkb = ebpf.program_mut("egress").unwrap().try_into()?;
    egress_program.load()?;

    let egress_stats_map = PerfEventArray::try_from(ebpf.take_map("TX_STATS").unwrap())?;
    let (shutdown_tx, _) = broadcast::channel(1);
    let (tx, _) = mpsc::unbounded_channel();
    let handles = noct::read_event_array(egress_stats_map, tx, shutdown_tx.subscribe())?;

    shutdown_tx.send(())?;

    for handle in handles {
        assert!(handle.await.is_ok());
    }

    Ok(())
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
    let (shutdown_tx, _) = broadcast::channel(1);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let handles = noct::read_event_array(egress_stats_map, tx, shutdown_tx.subscribe())?;

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

    let msg = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("no event received"))?;
    rx.close();
    shutdown_tx.send(())?;

    let event = msg.event;
    assert_eq!(event.src_addr, IpAddr::V4(src_addr));
    assert_eq!(event.dst_addr, IpAddr::V4(dst_addr));
    assert_eq!(event.src_port, src_port);
    assert_eq!(event.dst_port, dst_port);
    assert_eq!(event.protocol, IpProto::UDP);
    assert_eq!(event.payload_len, 0);
    assert_eq!(usize::from(event.pkt_len), tot_len - Ethernet2Header::LEN);

    for handle in handles {
        assert!(handle.await.is_ok());
    }

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
    let (shutdown_tx, _) = broadcast::channel(1);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let handles = noct::read_event_array(egress_stats_map, tx, shutdown_tx.subscribe())?;

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

    let msg = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("no event received"))?;
    rx.close();
    shutdown_tx.send(())?;

    let event = msg.event;
    assert_eq!(event.src_addr, IpAddr::V4(src_addr));
    assert_eq!(event.dst_addr, IpAddr::V4(dst_addr));
    assert_eq!(event.src_port, src_port);
    assert_eq!(event.dst_port, dst_port);
    assert_eq!(event.protocol, IpProto::UDP);
    assert_eq!(usize::from(event.payload_len), payload.len());
    assert_eq!(usize::from(event.pkt_len), tot_len - Ethernet2Header::LEN);

    for handle in handles {
        assert!(handle.await.is_ok());
    }

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
    let (shutdown_tx, _) = broadcast::channel(1);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let handles = noct::read_event_array(egress_stats_map, tx, shutdown_tx.subscribe())?;

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

    let msg = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("no event received"))?;
    rx.close();
    shutdown_tx.send(())?;

    let event = msg.event;
    assert_eq!(event.src_addr, IpAddr::V4(src_addr));
    assert_eq!(event.dst_addr, IpAddr::V4(dst_addr));
    assert_eq!(event.src_port, src_port);
    assert_eq!(event.dst_port, dst_port);
    assert_eq!(event.protocol, IpProto::TCP);
    assert_eq!(event.payload_len, 0);
    assert_eq!(usize::from(event.pkt_len), tot_len - Ethernet2Header::LEN);

    for handle in handles {
        assert!(handle.await.is_ok());
    }

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
    let (shutdown_tx, _) = broadcast::channel(1);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let handles = noct::read_event_array(egress_stats_map, tx, shutdown_tx.subscribe())?;

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

    let msg = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("no event received"))?;
    rx.close();
    shutdown_tx.send(())?;

    let event = msg.event;
    assert_eq!(event.src_addr, IpAddr::V4(src_addr));
    assert_eq!(event.dst_addr, IpAddr::V4(dst_addr));
    assert_eq!(event.src_port, src_port);
    assert_eq!(event.dst_port, dst_port);
    assert_eq!(event.protocol, IpProto::TCP);
    assert_eq!(usize::from(event.payload_len), payload.len());
    assert_eq!(usize::from(event.pkt_len), tot_len - Ethernet2Header::LEN);

    for handle in handles {
        assert!(handle.await.is_ok());
    }

    Ok(())
}

#[tokio::test]
async fn test_single_packet_ip6_udp() -> anyhow::Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/noct"
    )))?;

    {
        let egress_program: &mut CgroupSkb = ebpf.program_mut("egress").unwrap().try_into()?;
        egress_program.load()?;
    }

    let egress_stats_map = PerfEventArray::try_from(ebpf.take_map("TX_STATS").unwrap())?;
    let (shutdown_tx, _) = broadcast::channel(1);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let handles = noct::read_event_array(egress_stats_map, tx, shutdown_tx.subscribe())?;

    let src_addr = Ipv6Addr::from_str("2001:db8::1").unwrap();
    let dst_addr = Ipv6Addr::from_str("2001:db8::2").unwrap();
    let src_port = 12000;
    let dst_port = 34000;
    let builder = build_l2_packet()
        .ipv6(src_addr.octets(), dst_addr.octets(), 10)
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

    let msg = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("no event received"))?;
    rx.close();
    shutdown_tx.send(())?;

    let event = msg.event;
    assert_eq!(event.src_addr, IpAddr::V6(src_addr));
    assert_eq!(event.dst_addr, IpAddr::V6(dst_addr));
    assert_eq!(event.src_port, src_port);
    assert_eq!(event.dst_port, dst_port);
    assert_eq!(event.protocol, IpProto::UDP);
    assert_eq!(usize::from(event.payload_len), payload.len());
    assert_eq!(usize::from(event.pkt_len), tot_len - Ethernet2Header::LEN);

    for handle in handles {
        assert!(handle.await.is_ok());
    }

    Ok(())
}

#[tokio::test]
async fn test_single_packet_ip6_tcp() -> anyhow::Result<()> {
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/noct"
    )))?;

    {
        let egress_program: &mut CgroupSkb = ebpf.program_mut("egress").unwrap().try_into()?;
        egress_program.load()?;
    }

    let egress_stats_map = PerfEventArray::try_from(ebpf.take_map("TX_STATS").unwrap())?;
    let (shutdown_tx, _) = broadcast::channel(1);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let handles = noct::read_event_array(egress_stats_map, tx, shutdown_tx.subscribe())?;

    let src_addr = Ipv6Addr::from_str("2001:db8::1").unwrap();
    let dst_addr = Ipv6Addr::from_str("2001:db8::2").unwrap();
    let src_port = 12000;
    let dst_port = 34000;
    let builder = build_l2_packet()
        .ipv6(src_addr.octets(), dst_addr.octets(), 10)
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

    let msg = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("no event received"))?;
    rx.close();
    shutdown_tx.send(())?;

    let event = msg.event;
    assert_eq!(event.src_addr, IpAddr::V6(src_addr));
    assert_eq!(event.dst_addr, IpAddr::V6(dst_addr));
    assert_eq!(event.src_port, src_port);
    assert_eq!(event.dst_port, dst_port);
    assert_eq!(event.protocol, IpProto::TCP);
    assert_eq!(usize::from(event.payload_len), payload.len());
    assert_eq!(usize::from(event.pkt_len), tot_len - Ethernet2Header::LEN);

    for handle in handles {
        assert!(handle.await.is_ok());
    }

    Ok(())
}

