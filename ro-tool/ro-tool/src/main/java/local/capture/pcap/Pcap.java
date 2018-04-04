package local.capture.pcap;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import com.sun.jna.Native;
import com.sun.jna.Pointer;

import local.capture.pcap.jnr.PcapInterface;
import local.capture.pcap.jnr.pcap_if;
import local.capture.pcap.jnr.pcap_pkthdr;

public class Pcap {
	private Logger logger = Logger.getLogger(getClass().getName()); 
	private PcapInterface pcap;
	private Pointer pPcap_t;

	public Pcap() {
		super();
		pcap = Native.loadLibrary("Wpcap", PcapInterface.class);
	}
	
	/**
	 * 
	 */
	public List<PcapIf> findAllDevs() throws PcapException{
		logger.fine("findAllDevs()");
		
		List<PcapIf> result = new ArrayList<>();
		
		Pointer ppAlldevsp = Native.getDirectBufferPointer(ByteBuffer.allocateDirect(Native.POINTER_SIZE));
		Pointer pErrbuf = Native.getDirectBufferPointer(ByteBuffer.allocateDirect(PcapInterface.PCAP_ERRBUF_SIZE));
		
		int n = pcap.pcap_findalldevs(ppAlldevsp, pErrbuf);
		
		if(n == -1){
			throw new PcapException(n, pErrbuf);
		}
		
		try {
			for(Pointer pAlldevsp = ppAlldevsp.getPointer(0); Pointer.NULL != pAlldevsp;  ) {
				pcap_if pcap_if = new pcap_if(pAlldevsp);
				
				PcapIf pcapIf = new PcapIf();
				pcapIf.setName(pcap_if.name.getString(0));
				pcapIf.setDescription(pcap_if.description.getString(0));
				result.add(pcapIf);
				
				pAlldevsp = pcap_if.next;
			}
			
		}finally {
			pcap.pcap_freealldevs(ppAlldevsp.getPointer(0));			
		}
		
		return result;
	}
	/**
	 * 
	 * @param device
	 * @param snaplen
	 * @param promisc
	 * @param to_ms
	 * @throws PcapException 
	 */
	public void openLive(String device, int snaplen, int promisc, int to_ms) throws PcapException {
		logger.fine("openLive(String device, int snaplen, int promisc, int to_ms)");
		if(pPcap_t != Pointer.NULL) {
			throw new PcapException("Pcap is already opened.");
		}
		Pointer pErrbuf = Native.getDirectBufferPointer(ByteBuffer.allocateDirect(PcapInterface.PCAP_ERRBUF_SIZE));
		Pointer pointer = pcap.pcap_open_live(device, snaplen, promisc, to_ms, pErrbuf);
		if(pointer == Pointer.NULL) {
			throw new PcapException(pErrbuf);
		}
		pPcap_t = pointer;
	}
	
	public void openLive(String device, int to_ms) throws PcapException {
		openLive(device, 65535, 65535, to_ms);
	}
	
	public void openLive(String device) throws PcapException {
		openLive(device, 1000);
	}
	
	public Pkt nextEx() throws PcapException {
		logger.fine("nextEx()");
		Pkt pkt = null;
		
		Pointer ppPkt_header = Native.getDirectBufferPointer(ByteBuffer.allocateDirect(Native.POINTER_SIZE));
		Pointer ppPkt_data = Native.getDirectBufferPointer(ByteBuffer.allocateDirect(Native.POINTER_SIZE));
		
		int n = pcap.pcap_next_ex(pPcap_t, ppPkt_header, ppPkt_data);
		if(-1 == n) {
			throw new PcapException(pcap.pcap_geterr(pPcap_t));
		}
		if(1 == n) {
			pcap_pkthdr pcap_pkthdr = new pcap_pkthdr(ppPkt_header.getPointer(0));
			logger.fine("pcap_pkthdr.ts.tv_sec:" + pcap_pkthdr.ts.tv_sec);
			logger.fine("pcap_pkthdr.ts.tv_usec:" + pcap_pkthdr.ts.tv_usec);
			
			PktHeader header = new PktHeader();
			header.setTime(pcap_pkthdr.ts.tv_sec * 1000L * 1000L + pcap_pkthdr.ts.tv_usec);
			header.setCapLen(pcap_pkthdr.caplen);
			header.setLen(pcap_pkthdr.len);
			
			byte[] pkt_data = ppPkt_data.getPointer(0).getByteArray(0, pcap_pkthdr.len);
			
			pkt = new Pkt();
			pkt.setHeader(header);
			pkt.setData(pkt_data);
			
		}
		return pkt;
	}
	
	public void close(){
		logger.fine("close()");
		try {
			pcap.pcap_close(pPcap_t);
			
		}finally {
			pPcap_t = Pointer.NULL;
		}
	}
}
