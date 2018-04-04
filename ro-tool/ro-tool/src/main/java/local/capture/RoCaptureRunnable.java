package local.capture;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.codec.binary.Hex;

import local.capture.pcap.Pcap;
import local.capture.pcap.PcapException;
import local.capture.pcap.Pkt;

class RoCaptureRunnable implements Runnable{
	private Logger logger = Logger.getLogger(getClass().getName());
	
	private Pcap pcap;
	
	
	
	/* (non-Javadoc)
	 * @see java.lang.Runnable#run()
	 */
	public RoCaptureRunnable(Pcap pcap) {
		super();
		this.pcap = pcap;
	}



	@Override
	public void run() {
		logger.fine("run()");
		
		while(!Thread.interrupted()) {
			Pkt pkt;
			try {
				pkt = pcap.nextEx();
				if(pkt != null) {
					logger.fine("time:" + System.currentTimeMillis() * 1000);
					logger.fine("pkt.getHeader().getTime():" + pkt.getHeader().getTime());
					logger.fine("pkt.getHeader().getCapLen():" + pkt.getHeader().getCapLen());
					logger.fine("pkt.getHeader().getLen():" + pkt.getHeader().getLen());
					
					if(logger.isLoggable(Level.FINE)) {
						logger.fine("pkt.getData():" + Hex.encodeHexString(pkt.getData()));
					}
				}
				
			} catch (PcapException e) {
				logger.log(Level.SEVERE, "pcap.nextEx()", e);
			}
		}
	}
}
