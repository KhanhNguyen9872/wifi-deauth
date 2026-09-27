import unittest
from collections import defaultdict
from types import SimpleNamespace
from unittest.mock import patch

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from wifi_deauth.wifi_deauth import Interceptor, ScanBand
from wifi_deauth.utils import BandType, frequency_to_channel


class ScanBandTest(unittest.TestCase):
    def make_interceptor(self, scan_band, custom_channels=None):
        interceptor = object.__new__(Interceptor)
        interceptor._channel_range = {
            channel: {} for channel in (1, 6, 11, 36, 44, 149)
        }
        interceptor._custom_target_ap_channels = custom_channels or []
        interceptor._scan_band = scan_band
        interceptor._debug_mode = False
        interceptor._scan_stats = {
            "frames_seen": 0,
            "ap_frames": 0,
            "parse_errors": 0,
            "channel_failures": 0,
        }
        interceptor._scan_channel_bssids = defaultdict(set)
        return interceptor

    @patch("wifi_deauth.wifi_deauth.print_input", side_effect=["invalid", "4", "2"])
    @patch("wifi_deauth.wifi_deauth.print_error")
    def test_prompt_retries_until_a_valid_choice(self, print_error, _print_input):
        self.assertEqual(ScanBand.T_24GHZ, Interceptor._ask_scan_band())
        self.assertEqual(2, print_error.call_count)

    def test_all_scans_every_supported_channel(self):
        interceptor = self.make_interceptor(ScanBand.ALL)
        self.assertEqual([1, 6, 11, 36, 44, 149], interceptor._get_channel_range())

    def test_24ghz_scans_channels_up_to_14(self):
        interceptor = self.make_interceptor(ScanBand.T_24GHZ)
        self.assertEqual([1, 6, 11], interceptor._get_channel_range())

    def test_5ghz_scans_channels_above_14(self):
        interceptor = self.make_interceptor(ScanBand.T_50GHZ)
        self.assertEqual([36, 44, 149], interceptor._get_channel_range())

    def test_band_filter_is_applied_to_custom_channels(self):
        interceptor = self.make_interceptor(ScanBand.T_50GHZ, [6, 36, 44])
        self.assertEqual([36, 44], interceptor._get_channel_range())

    def test_same_ssid_on_two_bssids_remains_two_targets(self):
        interceptor = self.make_interceptor(ScanBand.T_24GHZ)
        interceptor._custom_ssid_name = None
        interceptor._custom_bssid_addr = None
        interceptor._all_ssids = {band: {} for band in BandType}
        interceptor._current_channel_num = 1
        interceptor.target_ssid = None

        for bssid in ("02:00:00:00:00:01", "02:00:00:00:00:02"):
            packet = (
                RadioTap(present="Channel", ChannelFrequency=2412, ChannelFlags="2GHz")
                / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
                / Dot11Beacon()
                / Dot11Elt(ID="SSID", info=b"Shared WiFi")
            )
            interceptor._ap_sniff_cb(packet)

        self.assertEqual(2, len(interceptor._all_ssids[BandType.T_24GHZ]))

    def test_channel_14_frequency_is_not_misclassified_as_5ghz(self):
        self.assertEqual(14, frequency_to_channel(2484))

    @patch("wifi_deauth.wifi_deauth.subprocess.run")
    def test_channel_discovery_prefers_iw_phy_and_ignores_disabled_channels(self, run):
        run.side_effect = [
            SimpleNamespace(returncode=0, stdout="Interface wlan0\n\twiphy 2\n", stderr=""),
            SimpleNamespace(
                returncode=0,
                stdout=(
                    "\t* 2412 MHz [1] (20.0 dBm)\n"
                    "\t* 5180 MHz [36] (23.0 dBm)\n"
                    "\t* 5260 MHz [52] (disabled)\n"
                    "\t* 5955 MHz [1] (23.0 dBm)\n"
                ),
                stderr="",
            ),
        ]
        interceptor = self.make_interceptor(ScanBand.ALL)
        interceptor.interface = "wlan0"

        self.assertEqual([1, 36], interceptor._get_channels())
        self.assertEqual(["iw", "phy", "phy2", "info"], run.call_args_list[1].args[0])

    @patch("wifi_deauth.wifi_deauth.subprocess.run")
    def test_channel_discovery_falls_back_to_iwlist(self, run):
        run.side_effect = [
            SimpleNamespace(returncode=1, stdout="", stderr="iw failed"),
            SimpleNamespace(
                returncode=0,
                stdout="Channel 01 : 2.412 GHz\nChannel 36 : 5.180 GHz\nCurrent Frequency:2.412 GHz",
                stderr="",
            ),
        ]
        interceptor = self.make_interceptor(ScanBand.ALL)
        interceptor.interface = "wlan0"

        self.assertEqual([1, 36], interceptor._get_channels())

    @patch("wifi_deauth.wifi_deauth.subprocess.run")
    def test_failed_channel_change_does_not_update_current_channel(self, run):
        run.return_value = SimpleNamespace(returncode=1, stdout="", stderr="not supported")
        interceptor = self.make_interceptor(ScanBand.ALL)
        interceptor.interface = "wlan0"
        interceptor._current_channel_num = 1

        self.assertFalse(interceptor._set_channel(36))
        self.assertEqual(1, interceptor._current_channel_num)

    @patch("wifi_deauth.wifi_deauth.print_info")
    @patch.object(Interceptor, "_start_initial_ap_scan", return_value=None)
    def test_scan_only_exits_without_selecting_a_target(self, _scan, print_info):
        interceptor = self.make_interceptor(ScanBand.ALL)
        interceptor._scan_only = True
        interceptor.target_ssid = None

        interceptor.run()

        print_info.assert_called_once_with("Scan-only mode complete; no target was selected")

    @patch("wifi_deauth.wifi_deauth.sniff")
    @patch("wifi_deauth.wifi_deauth.print_info")
    @patch("wifi_deauth.wifi_deauth.printf")
    def test_scan_passes_and_dwell_are_forwarded_to_sniff(self, _printf, _print_info, sniff):
        interceptor = self.make_interceptor(ScanBand.T_24GHZ, [1, 6])
        interceptor.interface = "wlan0"
        interceptor._custom_ssid_name = None
        interceptor._all_ssids = {band: {} for band in BandType}
        interceptor._scan_dwell = 0.25
        interceptor._scan_passes = 2
        interceptor._set_channel = lambda channel: setattr(interceptor, "_current_channel_num", channel) or True

        interceptor._scan_channels_for_aps()

        self.assertEqual(4, sniff.call_count)
        self.assertTrue(all(call.kwargs["timeout"] == 0.25 for call in sniff.call_args_list))
        self.assertTrue(all(call.kwargs["store"] is False for call in sniff.call_args_list))


if __name__ == "__main__":
    unittest.main()
