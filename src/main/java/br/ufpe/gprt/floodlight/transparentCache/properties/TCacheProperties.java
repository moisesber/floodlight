package br.ufpe.gprt.floodlight.transparentCache.properties;

import java.io.File;
import java.io.FileInputStream;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TCacheProperties {
	
	private final String propertiesDefaultFile = "src/main/resources/transparentCache.properties";
	private Properties props;
	private Logger logger;
	
	
	private static final String CACHE_ADDRESS_STRING = "CacheAddress";
	private static final String DELAY_LOG_FILE_STRING = "DelaysLogFile";
	private static final String ENABLE_DELAY_LOGGING_STRING = "EnableDelayLogging";

	//default values
	private final String defaultCacheAddress = "192.168.1.3";
	private final String defaultDelaysLogFile = "delays.log";
	private final boolean defaultEnableDelayLogging = true;
	
	private boolean enableDelayLogging;
	private static TCacheProperties instance;
	
	private TCacheProperties(){
		logger = LoggerFactory.getLogger(TCacheProperties.class);

		props = new Properties();
		initDefaulProperties();
		
		FileInputStream fileInput;
		try {
			fileInput = new FileInputStream(new File(propertiesDefaultFile));
			this.props.load(fileInput);
			fileInput.close();

		} catch (Exception e) {
			logger.error("Error loading property file, using default values");
			e.printStackTrace();
		}
		
		this.enableDelayLogging = Boolean.parseBoolean(this.props.getProperty(ENABLE_DELAY_LOGGING_STRING));
	}
	
	public static TCacheProperties getInstance(){
		if(instance == null){
			instance = new TCacheProperties();
		}
		
		return instance;
	}

	private void initDefaulProperties(){
		this.props.put(CACHE_ADDRESS_STRING, defaultCacheAddress);
		this.props.put(DELAY_LOG_FILE_STRING, defaultDelaysLogFile);
		this.props.put(ENABLE_DELAY_LOGGING_STRING, defaultEnableDelayLogging);
	}
	
	public String getCacheAddress(){
		return this.props.getProperty(CACHE_ADDRESS_STRING);
	}
	
	public String getDelaysLogFile(){
		return this.props.getProperty(DELAY_LOG_FILE_STRING);
	}
	
	public boolean isDelayLoggingEnabled(){
		return this.enableDelayLogging;
	}
}
