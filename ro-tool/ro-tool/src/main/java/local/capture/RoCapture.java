package local.capture;

import java.io.IOException;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import local.capture.pcap.Pcap;
import local.capture.pcap.PcapException;
import local.capture.pcap.PcapIf;

public class RoCapture {
	
	public static void main(String[] args) throws IOException, RoCaptureException, InterruptedException  {
//		Logger logger = Logger.getLogger(RoCapture.class.getName());
		Logger logger = Logger.getLogger(RoCapture.class.getPackage().getName());
		
		ConsoleHandler consoleHandler = new ConsoleHandler();
		consoleHandler.setLevel(Level.ALL);
		logger.addHandler(consoleHandler);
		
		logger.setUseParentHandlers(false);
		logger.setLevel(Level.ALL);
		
		RoCapture roPacketCapture = new RoCapture();
		
		roPacketCapture.start();
		
		Thread.sleep(10000);
		
		roPacketCapture.stop();
	}

	private Logger logger = Logger.getLogger(getClass().getName());
	private Pcap pcap = new Pcap();
	private String interfaceName = null;  // Null is first found interface.
	private Thread thread;
	private RoCaptureRunnable runnable;
	
	/**
	 * @return the interfaceName
	 */
	public String getInterfaceName() {
		return interfaceName;
	}

	/**
	 * @param interfaceName the interfaceName to set
	 */
	public void setInterfaceName(String interfaceName) {
		this.interfaceName = interfaceName;
	}

	private PcapIf findDev() throws RoCaptureException {
		logger.fine("findAllDevs()");
		try {
			PcapIf result = null;
			for (PcapIf pcapIf: pcap.findAllDevs()) {
				logger.fine("pcapIf.getName():" + pcapIf.getName());
				logger.fine("pcapIf.getDescription():" + pcapIf.getDescription());
				
				if(result == null) {
					if(interfaceName == null || interfaceName.equals(pcapIf.getName())) {
						result = pcapIf;
					}
				}
			}
			
			if(result == null) {
				throw new RoCaptureException("Not found enabled adapter.");	
			}
			return result;
			
		} catch (PcapException e) {
			throw new RoCaptureException(e); 
		}
	}
	
	private void openLive(PcapIf pcapIf) throws RoCaptureException {
		try {
			pcap.openLive(pcapIf.getName());
			
		} catch (PcapException e) {
			pcap.close();
			throw new RoCaptureException(e);
		}
	}
	
	public void start() throws RoCaptureException {
		logger.info("start()");
		
		if(thread != null) {
			throw new RoCaptureException("Already started.");
		}
		
		PcapIf pcapIf = findDev();
		openLive(pcapIf);
		
		runnable = new RoCaptureRunnable(pcap);
		thread = new Thread(runnable);
		thread.start();
	}
	
	public void stop() {
		logger.info("stop()");
		if(thread != null) {
			thread.interrupt();
			try {
				thread.join();
				
			} catch (InterruptedException e) {
				logger.info("thread.join() is Interrupted.");
			}
		}
		pcap.close();
	}
}
