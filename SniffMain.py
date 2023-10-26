from winpcapy import *
import time
import sys
import libpcap
import winpcapy.winpcapy_types as wtypes
import Para

var=10

var=Para.para_to_Sniff()

class NewClass(WinPcap):

    def myrun(self, callback=None, limit=var):  # limit=0

        if self._handle is None:
            raise self.DeviceIsNotOpen()
        self._callback = callback
        wtypes.pcap_loop(self._handle, limit, self._callback_wrapper, None)
class MyClass(WinPcapUtils):

    def packet_printer_callback(win_pcap, param, header, pkt_data):      #重写WinPcapUtils中的packet_printer_callback方法，使其将packet数据以十六进制输出并保存。
        try:
            local_tv_sec = header.contents.ts.tv_sec
            ltime = time.localtime(local_tv_sec)
            timestr = time.strftime("%H:%M:%S", ltime)
            print("%s,%.6d len:%d" % (timestr, header.contents.ts.tv_usec, header.contents.len))
            pkt = int.from_bytes(pkt_data, byteorder='big', signed=True)
            pkt1 = hex(pkt)
            file = open("C:/Users/M/Desktop/test.txt", "a")
            file.write(pkt1)
            file.write('\n')
            print(pkt1)
        except KeyboardInterrupt:
            win_pcap.stop()
            sys.exit(0)
    def mycapture_on(pattern, callback):
        """
        :param pattern: a wildcard pattern to match the description of a network interface to capture packets on
        :param callback: a function to call with each intercepted packet
        """
        device_name, desc = WinPcapDevices.get_matching_device(pattern)
        if device_name is not None:
            with NewClass(device_name) as capture:
                capture.myrun(callback=callback)

