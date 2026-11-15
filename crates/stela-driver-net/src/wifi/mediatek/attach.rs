// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! One claimed MT7925 function taken from its registers to a managed station
//! link: `mt7925_pci_probe` identifies and boots it, `mt7925_regd_update`
//! programs its country, `mt7925_mac_init` and `mt7925_start` bring up its
//! MAC on mac80211's default channel, and `mt7925_add_interface` registers
//! its station interface, which a [`Station`] then keeps connected.
//!
//! MT7921 (Connac2) attaches only as far as `mt7921_pci_probe`'s firmware
//! boot: its station layer is not ported, so [`attach`] reports what the
//! booted function says ([`Booted`]) and returns
//! [`AttachError::StationNotPorted`] rather than a link.
use super::{
    acpi::Sar,
    bootstrap::{
        self, Controller,
        client::{
            self, Client, Environment, LinkControlError, ManagedClient, ManagedLink, PolicyError,
        },
    },
    firmware::{
        LoadError, Requests,
        clc::{Environment as ClcEnvironment, Inputs as ClcInputs},
    },
    identity::{Chip, PciIdentity},
    mailbox::CapabilityReport,
    mcu::device::Context,
    station::{Station, Wifi},
};
use crate::{
    Clock, Mac,
    bus::dma::{mapping::DmaDomain, memory::PageSource},
    firmware::Provider,
    wifi::{
        network::Network,
        regulatory::database::{self, Database},
    },
};
use alloc::sync::Arc;
use core::{any::Any, fmt, ptr::NonNull};
use stela_driver_base::entropy::Entropy;

/// The services and platform facts the attach borrows.
pub struct Inputs {
    pub firmware: &'static dyn Provider,
    pub pages: &'static dyn PageSource,
    pub clock: Clock,
    /// Whether `owner`'s function raises an MSI the caller has routed.
    pub vector: bool,
    /// `mt76_pci_aspm_supported`: whether the function's link enables ASPM.
    pub aspm: bool,
    /// regulatory.db, whose country the network names, or the world domain
    /// `00` cfg80211 starts from when it names none.
    pub database: Database,
    pub network: Network,
    pub sar: Sar,
    /// The source of the station's handshake nonces.
    pub entropy: Arc<dyn Entropy>,
}

/// Why the function did not reach a managed link. Every owner the device may
/// still reach stays held.
#[derive(Debug)]
pub enum AttachError {
    /// Only MT7925 and MT7921's firmware boot are ported.
    UnsupportedChip(PciIdentity),
    /// The firmware booted and answered its capability query, but the
    /// chip's station layer is not ported, so no link starts. The function
    /// stays held like any attach that failed after its firmware booted.
    StationNotPorted(Booted),
    /// No regulatory database loaded, so the radio may not transmit.
    NoRegulatoryDatabase,
    /// regulatory.db holds no usable rules for the network's country.
    Country([u8; 2], database::Error),
    Firmware(LoadError),
    Bootstrap(bootstrap::Error),
    /// Neither the capabilities nor the EEPROM report a station address.
    NoAddress,
    /// The country enables no channel the radio may start on.
    NoChannel,
    Client(client::Error),
    Policy(PolicyError),
    Link(LinkControlError),
}

/// What a function whose firmware booted reports before any station exists:
/// the chip, the station address and the bands its capability query named.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Booted {
    pub chip: Chip,
    /// The firmware's raw address, which is not validated or replaced.
    pub address: Option<Mac>,
    /// 2.4, 5 and 6 GHz, when the report carries a PHY.
    pub bands: Option<[bool; 3]>,
}

impl Booted {
    fn name(self) -> &'static str {
        match self.chip {
            Chip::Mt7921 => "MT7921",
            Chip::Mt7922 => "MT7922",
            Chip::Mt7925 => "MT7925",
        }
    }
}

impl fmt::Display for Booted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: firmware booted", self.name())?;
        match self.address {
            Some(Mac([a, b, c, d, e, g])) => write!(
                f,
                ", address {a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}"
            )?,
            None => f.write_str(", no address reported")?,
        }
        match self.bands {
            Some([ghz2, ghz5, ghz6]) => write!(
                f,
                ", bands 2.4 GHz {}, 5 GHz {}, 6 GHz {}",
                u8::from(ghz2),
                u8::from(ghz5),
                u8::from(ghz6)
            )?,
            None => f.write_str(", bands unreported")?,
        }
        f.write_str("; its station layer is not ported, so no Wi-Fi link starts")
    }
}

impl From<bootstrap::Error> for AttachError {
    fn from(error: bootstrap::Error) -> Self {
        Self::Bootstrap(error)
    }
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StationNotPorted(booted) => write!(f, "{booted}"),
            Self::Firmware(error) => write!(f, "{error}"),
            Self::Bootstrap(error) => write!(f, "{error}"),
            Self::Link(error) => write!(f, "{error}"),
            Self::NoRegulatoryDatabase => f.write_str("MT7925: no regulatory database"),
            Self::Country(alpha2, error) => write!(
                f,
                "MT7925: regulatory.db country {}: {error:?}",
                alpha2.escape_ascii()
            ),
            error => write!(f, "MT7925 attach: {error:?}"),
        }
    }
}

/// A kept station connection and what limits it without stopping it.
pub struct Attached<C: 'static> {
    pub station: Wifi<C>,
    /// The firmware offers its own regulatory domain
    /// (`MT7925_REGD_SUPPORTED`). The link programs and verifies
    /// regulatory.db's country instead, so the firmware's stays unused.
    pub firmware_domain_unused: bool,
}

/// Identify, boot and program the function `pci` names, then register its
/// station interface and keep it connected to `inputs.network`.
///
/// # Safety
/// [`Controller::new`]'s and [`Controller::install`]'s contracts hold for
/// `base..base + bytes`, `resource` and `domain`, with `inputs.pages` as the
/// page source: `resource` keeps the claimed function and its uncached BAR0
/// mapping, whose interrupts are off.
pub unsafe fn attach<C: 'static>(
    pci: PciIdentity,
    base: NonNull<u8>,
    bytes: usize,
    resource: Arc<C>,
    domain: Arc<dyn DmaDomain>,
    inputs: Inputs,
) -> Result<Attached<C>, AttachError> {
    match pci.chip() {
        Some(Chip::Mt7925) => {}
        Some(Chip::Mt7921) => {
            // SAFETY: forwarded from the caller.
            let booted = unsafe { boot_only(pci, base, bytes, resource, domain, &inputs) }?;
            return Err(AttachError::StationNotPorted(booted));
        }
        _ => return Err(AttachError::UnsupportedChip(pci)),
    }
    let alpha2 = inputs.network.country.unwrap_or(*b"00");
    let country = inputs
        .database
        .select(alpha2)
        .map_err(|error| AttachError::Country(alpha2, error))?;
    let owner: Arc<dyn Any> = resource.clone();
    // SAFETY: forwarded from the caller.
    let identity =
        unsafe { bootstrap::identify(pci, base, bytes, owner.clone(), inputs.clock, inputs.aspm) }?;
    // Both images load before the controller claims the function.
    let prepared = Requests::new(&identity)
        .load(inputs.firmware)
        .map_err(AttachError::Firmware)?;
    // SAFETY: forwarded from the caller.
    let mut controller =
        unsafe { Controller::new(identity, base, bytes, owner, resource, inputs.clock) }?;
    // SAFETY: forwarded from the caller.
    unsafe { controller.install(inputs.pages, domain, inputs.aspm) }?;
    controller.boot(&prepared)?;
    let chip_capabilities = controller
        .capabilities()
        .and_then(|report| report.observed().chip_flags())
        .unwrap_or(0);
    // SAFETY: `resource` keeps the function's policy ownership. Connac3's
    // request carries none of Connac2's ACPI, power-node or MTCL fields, and
    // the CLC's environment is the OS's `country_ie_env`, ENVIRON_ANY.
    unsafe {
        controller.execute_clc(ClcInputs {
            alpha2,
            environment: ClcEnvironment::Any,
            chip_capabilities,
            power_limits_node: false,
            power_type: 0,
            acpi_flags: 0,
            mtcl_configuration: 0,
            world_mtcl_configuration: 0,
        })
    }?;
    let plan = controller.regulatory_plan(&country, &inputs.sar)?;
    let firmware_domain_unused = controller.firmware_regulatory_domain();
    // SAFETY: the plan resolves the CLC's restrictions, the country and the
    // platform's SAR, and `resource` keeps them.
    unsafe { controller.execute_remaining(plan.inputs()) }?;
    // SAFETY: no peer, WTBL or key user exists yet.
    unsafe { controller.initialize_mac() }?;
    let channel = plan.default_channel().ok_or(AttachError::NoChannel)?;
    // SAFETY: the programmed domain holds `channel`.
    unsafe { controller.start(channel.band, channel.number as u8, channel.frequency_mhz) }?;
    let address = controller
        .capabilities()
        .and_then(|report| report.observed().mac())
        .ok_or(AttachError::NoAddress)?;
    // `mt7925_add_interface`'s first interface: BSS, OMAC and WMM 0, no band
    // yet, and the broadcast WCID `MT792x_WTBL_RESERVED - 0`.
    let context = Context {
        bss_index: 0,
        omac_index: 0,
        band_index: 0xff,
        wmm_index: 0,
        link_index: 0,
        broadcast_wcid: 19,
        address,
    };
    // SAFETY: the first interface of a fresh controller.
    let interface = unsafe { controller.register_interface(context) }?;
    // SAFETY: the controller and interface are this requester's, after its
    // completed bootstrap and policy; `resource` keeps their permission.
    let client = unsafe { Client::new(controller, interface) }.map_err(AttachError::Client)?;
    let managed = ManagedClient::new(client, country.clone(), Environment::Any)
        .map_err(|error| AttachError::Policy(error.error))?;
    let link =
        ManagedLink::new(managed, inputs.pages).map_err(|error| AttachError::Link(error.error))?;
    let link = if inputs.vector {
        link.with_vector()
    } else {
        link
    };
    Ok(Attached {
        station: Station::new(
            link,
            context,
            country,
            inputs.network,
            inputs.entropy,
            inputs.clock,
        ),
        firmware_domain_unused,
    })
}

/// `mt7921_pci_probe` as far as the firmware's boot: identify the function,
/// load both images, claim it, install its queues and boot, then read what
/// the capability query reported. No CLC, regulatory, MAC or station command
/// follows, because those are Connac3's here.
///
/// # Safety
/// As for [`attach`].
unsafe fn boot_only<C: 'static>(
    pci: PciIdentity,
    base: NonNull<u8>,
    bytes: usize,
    resource: Arc<C>,
    domain: Arc<dyn DmaDomain>,
    inputs: &Inputs,
) -> Result<Booted, AttachError> {
    let owner: Arc<dyn Any> = resource.clone();
    // SAFETY: forwarded from the caller.
    let identity =
        unsafe { bootstrap::identify(pci, base, bytes, owner.clone(), inputs.clock, inputs.aspm) }?;
    // Both images load before the controller claims the function.
    let prepared = Requests::new(&identity)
        .load(inputs.firmware)
        .map_err(AttachError::Firmware)?;
    let chip = identity.chip;
    // SAFETY: forwarded from the caller.
    let mut controller =
        unsafe { Controller::new(identity, base, bytes, owner, resource, inputs.clock) }?;
    // SAFETY: forwarded from the caller.
    unsafe { controller.install(inputs.pages, domain, inputs.aspm) }?;
    controller.boot(&prepared)?;
    Ok(booted(chip, controller.capabilities()))
}

/// What the booted firmware's capability report says, unaltered: no
/// address is invented when it carries none.
fn booted(chip: Chip, report: Option<&CapabilityReport>) -> Booted {
    let observed = report.map(CapabilityReport::observed);
    Booted {
        chip,
        address: observed.and_then(|report| report.mac()),
        bands: observed.and_then(|report| {
            let phy = report.phy()?;
            Some([
                phy.has_2ghz(),
                phy.has_5ghz(),
                report.six_ghz().unwrap_or(false),
            ])
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn booted_function_reports_its_chip_address_and_bands() {
        let booted = Booted {
            chip: Chip::Mt7921,
            address: Some(Mac([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e])),
            bands: Some([true, true, false]),
        };
        assert_eq!(
            AttachError::StationNotPorted(booted).to_string(),
            "MT7921: firmware booted, address 00:1a:2b:3c:4d:5e, \
             bands 2.4 GHz 1, 5 GHz 1, 6 GHz 0; \
             its station layer is not ported, so no Wi-Fi link starts"
        );
    }

    #[test]
    fn booted_mt7921_model_reports_its_bands_and_invents_no_address() {
        if crate::test_process::isolate_model() {
            return;
        }
        let mut f = bootstrap::tests::NativeFixture::new(Chip::Mt7921);
        f.install().unwrap();
        f.boot(Chip::Mt7921);
        // The model's capability payload names a PHY with 2.4 and 5 GHz and no
        // station address; the readout passes exactly that through.
        assert_eq!(
            booted(Chip::Mt7921, f.controller.capabilities()),
            Booted {
                chip: Chip::Mt7921,
                address: None,
                bands: Some([true, true, false]),
            }
        );
        f.retire();
    }

    #[test]
    fn missing_observations_are_named_not_invented() {
        let text = Booted {
            chip: Chip::Mt7921,
            address: None,
            bands: None,
        }
        .to_string();
        assert!(text.contains("no address reported"), "{text}");
        assert!(text.contains("bands unreported"), "{text}");
    }
}
