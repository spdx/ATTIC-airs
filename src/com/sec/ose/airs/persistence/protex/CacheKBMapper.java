package com.sec.ose.airs.persistence.protex;

import com.sec.ose.airs.domain.autoidentify.ProtexIdentificationInfo;

public interface CacheKBMapper {
	public String getLicenseIDByName(String licenseName);
	public String getLicenseNameByID(String licenseId);
	
	public String getComponentIDByName(String componentName);
	
	public ProtexIdentificationInfo getComponentIDAndVersionIDWithNames(String componentName, String versionName);
	public ProtexIdentificationInfo getComponentVersionNamesWithIDs(String componentID, String versionID);
	
	public String getComponentVersionIDByComponentIDAndVersionName(String componentId, String componentVersionName);
	public String getComponentIDByNameAndVersionName(String componentName, String versionName);
	public String getComponentIDByNameAndLicenseIDAndVersionName(String componentName, String licenseId, String versionName);
	
	
	public void insertComponent(String componentID, String componentName);
	public void insertComponentVersion(String componentID, String componentName, String versionID, String versionName);
	public void insertLicense(String licenseID, String licenseName);
}
