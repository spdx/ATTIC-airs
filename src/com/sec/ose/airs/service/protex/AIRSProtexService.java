/**
 * Copyright(C) 2013-2014 Samsung Electronics Co., Ltd. All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
*/
package com.sec.ose.airs.service.protex;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.spdx.rdfparser.InvalidSPDXAnalysisException;
import org.spdx.rdfparser.SPDXDocument;
import org.spdx.rdfparser.SPDXDocumentFactory;
import org.spdx.rdfparser.SPDXFile;

import com.blackducksoftware.sdk.fault.SdkFault;
import com.blackducksoftware.sdk.protex.common.UsageLevel;
import com.blackducksoftware.sdk.protex.component.custom.CustomComponent;
import com.blackducksoftware.sdk.protex.component.standard.StandardComponent;
import com.blackducksoftware.sdk.protex.component.version.ComponentVersion;
import com.blackducksoftware.sdk.protex.license.GlobalLicense;
import com.blackducksoftware.sdk.protex.license.LicenseInfo;
import com.blackducksoftware.sdk.protex.project.codetree.discovery.StringSearchDiscovery;
import com.blackducksoftware.sdk.protex.project.codetree.identification.CodeMatchIdentificationDirective;
import com.blackducksoftware.sdk.protex.project.codetree.identification.CodeMatchIdentificationRequest;
import com.blackducksoftware.sdk.protex.project.codetree.identification.DeclaredIdentificationRequest;
import com.blackducksoftware.sdk.protex.project.codetree.identification.StringSearchIdentificationRequest;
import com.blackducksoftware.sdk.protex.project.localcomponent.LocalComponentRequest;
import com.blackducksoftware.sdk.protex.report.Report;
import com.sec.ose.airs.Properties;
import com.sec.ose.airs.domain.autoidentify.AutoIdentifyOptions;
import com.sec.ose.airs.domain.autoidentify.AutoIdentifyResult;
import com.sec.ose.airs.domain.autoidentify.ProtexIdentificationInfo;
import com.sec.ose.airs.domain.autoidentify.SPDXFileDTO;
import com.sec.ose.airs.domain.autoidentify.SPDXPackageDTO;
import com.sec.ose.airs.service.AIRSService;
import com.sec.ose.airs.service.AutoIdentifyService;

/**
 * 
 * 
 * @author ytaek.kim
 */
public class AIRSProtexService implements AIRSService {
	private static Log log = LogFactory.getLog(AIRSProtexService.class);
	
	ProtexSDKAPIService svc = new ProtexSDKAPIService();
	
	// string literals
	final String LICENSE_DELIMITER = "AIRS_LABELMAP_LICENSEID";
	final String COMPONENT_VERSION_DELIMITER = "AIRS_LABELMAP_COMPONENTID_VERSIONID";

	// label map
	public HashMap<String, String> licenseLabelMap = new HashMap<String, String>();
	public HashMap<String, String> componentVersionlabelMap = new HashMap<String, String>();
	// protex db cache maps
	private HashMap<String, String> componentMap = new HashMap<String, String>();
	private HashMap<String, String> localComponentNameMap = new HashMap<String, String>();
	
	public ProtexSDKAPIService getProtexSDKAPIService() {
		return svc;
	}
	
	@Override
	public void init(String protexServerIP, String userID, String password) throws Exception {
		svc.init(protexServerIP, userID, password);		
	}
	
	@Override
	public boolean identifyUsingSPDX(String targetProjectId, SPDXFileDTO sourceSpdxFile, SPDXFileDTO targetSpdxFile, PrintStream out) {
		
		ProtexIdentificationInfoService iiServ = new ProtexIdentificationInfoService();
		List<ProtexIdentificationInfo> infoList = iiServ.extractIdentificationInfoList(sourceSpdxFile); 

		if (infoList == null || infoList.size() < 1)
			return false;
		
		out.println(" > Identifying " + targetSpdxFile.getName() );
		
		for (ProtexIdentificationInfo info : infoList) {
			log.debug(" >> Identifing: " + info);

			String newLicenseId = this.licenseLabelMap.get(info.getLicense());
			String newComponentName = info.getComponent();
			String newVersionName = info.getVersion();
			String newComponentId = "";
			String newVersionId = "";
			
			// TODO - Need License check module 
			String newLicenseName = info.getLicense();
//			if (newLicenseName == null) {
//				log.error("License Name is not found: " + newLicenseId);
//				continue;
//			}
			
			// match type
			String matchType = info.getDiscoveryType();
			if(info.getResolutionType().equals("Declared"))
				matchType = ProtexIdentificationInfo.PATTERN_MATCH;

			String label = this.componentVersionlabelMap.get(info.getComponent() + "#" + info.getVersion());
			// component+version id valid check
			if (this.getComponentIDAndVersionIDWithNames(info.getComponent(), info.getVersion()) == null &&
					this.getComponentIDByName(info.getComponent()) == null) {
				// check already local component exists
				String localComponentId = this.getLocalComponentId(targetProjectId, newComponentName, newLicenseId, newLicenseName);
				//String localComponentId = this.createLocalComponent(targetProjectId, newComponentName, newLicenseId);
				label = localComponentId + "#" + "Unspecified";
			}
			
			if ("".equals(ObjectUtils.toString(label))) {
				log.error("fail to find component id: " + info.getComponent() + ", SKIP this file: " + info.getFilePath());
				continue;
			}

			String[] items = StringUtils.split(label, "#");
			newComponentId = items[0];
			newVersionId = items[1];
			
			// version set when unspecified
			if ("Unspecified".equals(newVersionName)) {
				newVersionName = "";
				newVersionId = "";
			}
			
			ProtexIdentificationInfo newInfo = new ProtexIdentificationInfo();
			newInfo.setFilePath(targetSpdxFile.getName());
			newInfo.setComponent(newComponentName);
			newInfo.setDiscoveryType(matchType);
			newInfo.setComponentID(newComponentId);
			newInfo.setVersionID(newVersionId);
			newInfo.setLicense(newLicenseName);
			newInfo.setLicenseID(newLicenseId);
			
			boolean identifyResult = this.identifyRequest(targetProjectId, newInfo);
			if (!identifyResult)
				continue;
		}
		return true;

	}
	
	
	@Override
	public AutoIdentifyResult autoIdentify(List<String> SPDXFileNameList, String targetProjectId, PrintStream out) {
		out.println("Start AutoIdentify to projectId: " + targetProjectId);
		out.println(" > Analyze SPDX Document(s) ...");
		AutoIdentifyService aiSvc = new AutoIdentifyService();
		AutoIdentifyResult aiResult = new AutoIdentifyResult();
		
		
		/////////////////////////////////////////////////////////////
		// 1. create package from spdx file and insert it to local db
		// and hold package id list
		// and Build Label map
		List<Integer> pkgIdList = new ArrayList<Integer>();
		for(String path : SPDXFileNameList) {
			out.println(" >> Read identification info from file: " + path);
			
			try {
				SPDXDocument doc = null;
				try {
					doc = SPDXDocumentFactory.creatSpdxDocument(path);
				} catch (IOException e) {
					log.error(e.getMessage());
					throw e;
				} catch (InvalidSPDXAnalysisException e) {
					log.error(e.getMessage());
					throw e;
				}

				String comment = doc.getCreatorInfo().getComment();
				
				// parsing label maps
				String[] lines = StringUtils.split(comment, "\n");
				boolean licenseLine = false;
				boolean compVerLine = false;
				
				for (String line : lines) {
					if (LICENSE_DELIMITER.equals(line)) {
						licenseLine = true;
						compVerLine = false;
						continue;
					} else if (COMPONENT_VERSION_DELIMITER.equals(line)) {
						compVerLine = true;
						licenseLine = false;
						continue;
					} else if ("\n".equals(line)) {
						licenseLine = compVerLine = false;
					}
					
					if (licenseLine) {
						String[] items = StringUtils.split(line, "=");
						if (!licenseLabelMap.containsKey(items[0])) {
							licenseLabelMap.put(items[0], items[1]);
						}
					} else if (compVerLine) {
						String[] items = StringUtils.split(line, "=");
						if (!componentVersionlabelMap.containsKey(items[0])) {
							componentVersionlabelMap.put(items[0], items[1]);
						}
					}
				}
				
				SPDXPackageDTO pkg = aiSvc.convertParserFormatToAIRSDB(doc);
				aiResult.getSourceSPDXPackageList().add(pkg);
				pkgIdList.add(aiSvc.insertSPDXPackageDataOnlyHavingIdentificationInfo(pkg));
				
				// FOR GC (reduce memory consumption ...)
				pkg.setFileList(null);
			} catch (Exception e) {
				log.error("SPDX Document Parsing failed: " + path + "\n" + e.getMessage());
				return null;
			}
		}
		
		out.println(" > Analyze current project information ...");
		///////////////////////////////////////////////////////////
		// 2. Create current project's SPDX document
		String currentProjectSPDXContent;
		try {
			currentProjectSPDXContent = svc.getSPDXReportContentString(targetProjectId, "org", "orgFile", "sec", "system", "");
		} catch (SdkFault e1) {
			log.error(e1.getMessage());
			out.println("Error occured when creating current project's SPDX document");
			return null;
		}
		
		// parsing it, and hold it in memory
		// TODO - in phase 2, it better to go to DB.
		SPDXPackageDTO tgtPkg = null;
		try {
			// TODO - encoding 처리
			tgtPkg = aiSvc.parseSPDXDocumentContent(currentProjectSPDXContent, "UTF-8");
		} catch (Exception e) {
			log.error("Couldn't analyze current project information.\nPlease contact admin.\n" + e.getMessage());
			return null;
		}
		
		out.println(" > Start Auto Identify processing ...\n");
		
		///////////////////////////////////////////////////////////		
		// 3. Auto Identify!
		AutoIdentifyOptions options = new AutoIdentifyOptions();
		
		String pMessage = null;
		int aiCount = 0;
		int aiError = 0;
		int multipleMatchedCount = 0;
		int noMathcedFileCount = 0;
		int totalFileCount = 0;
		int targetFileCount = tgtPkg.getFileList().size();
		for (SPDXFileDTO targetFile : tgtPkg.getFileList()) {
			totalFileCount++;
			out.println( "(" + totalFileCount + "/" + targetFileCount + ") " + targetFile.getName() + " checking...");
			List<SPDXFileDTO> fileList = aiSvc.getFileListByComparingHashCodeAndIdentificaionInfo(pkgIdList, targetFile, options);

			if (fileList != null) {
				// AI success
				if (fileList.size() == 1) {
					if (this.identifyUsingSPDX(targetProjectId, fileList.get(0), targetFile, out)) {
						pMessage = targetFile.getName() + ": Auto-identified.";
						aiCount++;
					} else {
					// CANNOT Happen for now.
						log.error("Filelist has a same matched file, but no ident info. THIS SHOULDn't happen");
						pMessage = targetFile.getName() + ": has a same matched file, but no identification info";
						aiError++;
					}
				} else if (fileList.size() > 1) {
					pMessage = targetFile.getName() + ": has multiple matched files with different identification data.";
					multipleMatchedCount++;
					aiResult.getFailedPairList().add(aiResult.new MatchedFilePair(targetFile, fileList));
				// No Matched
				} else if (fileList.size() == 0){
					pMessage = targetFile.getName() + ": has no matched file";
					noMathcedFileCount++;
				}
			// AI FAIL
			} else {
				log.error("Auto-identify Failed.THIS SHOULDn't happen");
				pMessage = targetFile.getName() + ": Auto-identify Failed.";
			}
						
			out.println(" >> " + pMessage);
		}
		
		/////////////////////////////////////////////////////
		// refresh bom
		// moved from pattern match
		try {
			svc.getBomAPI().refreshBom(targetProjectId, Boolean.TRUE, Boolean.FALSE);
			out.println("BOM Refreshing (it takes some minutes) ...");
		} catch (SdkFault e) {
			log.error("error when refresh bom lastly");
		}
		/////////////////////////////////////////////////////
		
		// empty source spdx package in local db
		for (int packageId : pkgIdList)
			aiSvc.deleteSPDXPackage(packageId);
		
		aiResult.setAiCount(aiCount);
		aiResult.setAiError(aiError);
		aiResult.setMultipleMatchedCount(multipleMatchedCount);
		aiResult.setNoMathcedFileCount(noMathcedFileCount);
		aiResult.setTotalFileCount(totalFileCount);
		
		out.println("AI Finished!");
		out.println("+----------------------------------------------+");
		out.println("ㅣ Total File count : " + aiResult.getTotalFileCount());
		out.println("ㅣ Auto-identified count : " + aiResult.getAiCount());
		out.println("ㅣ same matched file, but error : " + aiError);
		out.println("ㅣ multiple matched count : " + multipleMatchedCount);
		out.println("ㅣ no matched file count : " + noMathcedFileCount);
		out.println("+----------------------------------------------+");
		
		return aiResult;
	}

	@Override
	public AutoIdentifyResult autoIdentifyByProjectName(List<String> SPDXFileNameList,
			String targetProjectName, PrintStream out) {
		try {
			return this.autoIdentify(SPDXFileNameList, svc.getProjectAPI().getProjectByName(targetProjectName).getProjectId(), out);
		} catch (SdkFault e) {
			log.error(e.getMessage());
			return null;
		}
	}

	@Override
	public boolean export(String projectId, String targetFilePath,
			String packageName, String packageFileName,
			String organizationName, String creatorName, String creatorEmail,
			PrintStream out) throws Exception {
		out.println("Start SPDX Export - ProjectId:" + projectId);
		
		out.println(" > Generate SPDX Report Contents from server...");
        Report report = svc.getSPDXReport(projectId, packageName, packageFileName, organizationName, creatorName, creatorEmail);
        if (report == null) {
        	return false;
        }

        out.println(" > Get project Identification info from server...");
        
        HashMap<String, String> exportLicenseLabelMap = new HashMap<String, String>();
        HashMap<String, String> exportComponentVersionLabelMap = new HashMap<String, String>();
		HashMap<String, List<ProtexIdentificationInfo>> identificationInfoList = this.getIdentificationInfoList(projectId, exportLicenseLabelMap, exportComponentVersionLabelMap, out);
        
		// when empty project (no pending/identify list) 
		if (identificationInfoList == null) {
			out.println("project: " + projectId + " is empty or not analyzed yet.");
			System.exit(0);
		}
		
		// Read SPDX and write identification info to it.
		SPDXDocument doc; 
		try {
	        StringBuilder sb = new StringBuilder();
			BufferedReader SPDXReportReader = null;
			SPDXReportReader = new BufferedReader(new InputStreamReader(report.getFileContent().getInputStream(), "UTF-8"));
			String tmpStr = null;
			while((tmpStr = SPDXReportReader.readLine()) != null) {
				sb.append(tmpStr);
				sb.append("\n");
			}
			
			out.println(" > Rebuild SPDX Report...");
			InputStream is = new ByteArrayInputStream(sb.toString().getBytes("UTF-8")); 
			doc = SPDXDocumentFactory.creatSpdxDocument(is, null, null);
			is.close();
			
			SPDXFile[] fileList = null;
			if(doc.getSpdxPackage() != null) {
				fileList = doc.getSpdxPackage().getFiles();
			}
			
			out.println(" > Write Identification info to SPDX Report...");
			for (Map.Entry<String, List<ProtexIdentificationInfo>> entrySet : identificationInfoList.entrySet()) {
				String identifyFilePath = entrySet.getKey();
				List<ProtexIdentificationInfo> infoList = entrySet.getValue();
				
				String fileGetName = "";
				for (SPDXFile file : fileList) {
					fileGetName = file.getName();
					if (fileGetName.equals(identifyFilePath)) {
						String infoStr = "";
						for (ProtexIdentificationInfo info : infoList) {
							infoStr += info + "\n";
						}
						file.setComment(infoStr + "\n" + file.getComment());
						break;
					}
				}
			}
		
			// Write document/AIRS version
			String ver = "\n\nSPDX-AIRS:" + Properties.AIRS_SPDX_VERSION + "/AIRS:" + Properties.VERSION + "\n\n";
			
			// Write labelmap
			sb = new StringBuilder();
			sb.append(LICENSE_DELIMITER);
			sb.append("\n");
			for (Map.Entry<String, String> entrySet : exportLicenseLabelMap.entrySet()) {
				sb.append(entrySet.getKey());
				sb.append("=");
				sb.append(entrySet.getValue());
				sb.append("\n");				
			}
			sb.append(COMPONENT_VERSION_DELIMITER);
			sb.append("\n");
			for (Map.Entry<String, String> entrySet : exportComponentVersionLabelMap.entrySet()) {
				sb.append(entrySet.getKey());
				sb.append("=");
				sb.append(entrySet.getValue());
				sb.append("\n");
			}
			sb.append("\n");
			
			doc.getCreatorInfo().setComment(doc.getCreatorInfo().getComment() + ver + sb.toString());
			doc.getModel().write(new FileOutputStream(targetFilePath));
			doc.getModel().close();
			
			out.println("Success exporting SPDX to " + targetFilePath);
			
		} catch(IOException e) {
			log.error(e.getMessage());
			return false;
		} catch (InvalidSPDXAnalysisException e) {
			log.error(e.getMessage());
			return false;
		}
		
		return true;
	}
	
	@Override
	public boolean exportByProjectName(String projectName,
			String targetFilePath, String packageName, String packageFileName,
			String organizationName, String creatorName, String creatorEmail,
			PrintStream out) throws Exception{
		
		return export(svc.getProjectAPI().getProjectByName(projectName).getProjectId(), targetFilePath, packageName, packageFileName, organizationName, creatorName, creatorEmail, out);
	}

	

	protected boolean identifyRequest(String targetProjectId, ProtexIdentificationInfo info) {
		String matchType = info.getDiscoveryType();
		String newComponentId = info.getComponentID();
		String newVersionId = info.getVersionID();
		
		LicenseInfo identifiedLicenseInfo = new LicenseInfo();
		identifiedLicenseInfo.setLicenseId(info.getLicenseID());
		identifiedLicenseInfo.setName(info.getLicense());
		
		// IDENTIFY
		if (ProtexIdentificationInfo.STRING_SEARCH.equals(matchType)) {
			if (newComponentId == null) {
				log.error("fail to create local component id. SKIP this file: " + info.getFilePath());
				return false;
			}
	
			List<StringSearchDiscovery> listStringSearchDiscovery = svc.getStringSearchDiscoveries(targetProjectId, info.getFilePath());
			for (StringSearchDiscovery oStringSearchDiscovery : listStringSearchDiscovery) {
				StringSearchIdentificationRequest oStringSearchIdentificationRequest = new StringSearchIdentificationRequest();
				oStringSearchIdentificationRequest.setIdentifiedComponentId(newComponentId);
				oStringSearchIdentificationRequest.setIdentifiedVersionId("");
				oStringSearchIdentificationRequest.setIdentifiedUsageLevel(UsageLevel.SNIPPET);
				oStringSearchIdentificationRequest.setIdentifiedLicenseInfo(identifiedLicenseInfo);
				oStringSearchIdentificationRequest.setFolderLevelIdentification(false);
				oStringSearchIdentificationRequest.setStringSearchId(oStringSearchDiscovery.getStringSearchId());
				oStringSearchIdentificationRequest.getMatchLocations().addAll(oStringSearchDiscovery.getMatchLocations());
				svc.addStringSearchIdentification(targetProjectId, oStringSearchDiscovery.getFilePath(), oStringSearchIdentificationRequest);
	
				// TODO - pending 
	//			boolean pendingExist = false;
	//			for (StringSearchMatchLocation location : oStringSearchDiscovery.getMatchLocations()) {
	//				if (location.getIdentificationStatus() == IdentificationStatus.PENDING_IDENTIFICATION) {
	//					pendingExist = true;
	//					break;
	//				}
	//			}
	//			
	//			if (pendingExist) {
	//				StringSearchIdentificationRequest oStringSearchIdentificationRequest = new StringSearchIdentificationRequest();
	//				oStringSearchIdentificationRequest.setIdentifiedComponentId(newComponentId);
	//				oStringSearchIdentificationRequest.setIdentifiedVersionId("");
	//				oStringSearchIdentificationRequest.setIdentifiedUsageLevel(UsageLevel.SNIPPET);
	//				oStringSearchIdentificationRequest.setIdentifiedLicenseInfo(identifiedLicenseInfo);
	//				oStringSearchIdentificationRequest.setFolderLevelIdentification(false);
	//				oStringSearchIdentificationRequest.setStringSearchId(oStringSearchDiscovery.getStringSearchId());
	//				oStringSearchIdentificationRequest.getMatchLocations().addAll(oStringSearchDiscovery.getMatchLocations());
	//				apiSvc.addStringSearchIdentification(targetProjectId, oStringSearchDiscovery.getFilePath(), oStringSearchIdentificationRequest);
	//			}						
			}
			
			
		} else if (ProtexIdentificationInfo.CODE_MATCH.equals(matchType)) {
			CodeMatchIdentificationRequest codeMatchIdentificationRequest = new CodeMatchIdentificationRequest();
			
			codeMatchIdentificationRequest.setDiscoveredVersionId(newVersionId);
			codeMatchIdentificationRequest.setDiscoveredComponentId(newComponentId);
			codeMatchIdentificationRequest.setIdentifiedVersionId(newVersionId);
			codeMatchIdentificationRequest.setIdentifiedComponentId(newComponentId);
			codeMatchIdentificationRequest.setCodeMatchIdentificationDirective(CodeMatchIdentificationDirective.SNIPPET_AND_FILE);
			codeMatchIdentificationRequest.setIdentifiedUsageLevel(UsageLevel.SNIPPET);
			codeMatchIdentificationRequest.setIdentifiedLicenseInfo(identifiedLicenseInfo);
	
			svc.addCodeMatchIdentification(targetProjectId, "/" + info.getFilePath(), codeMatchIdentificationRequest);
		} else if (ProtexIdentificationInfo.PATTERN_MATCH.equals(matchType)) {
			DeclaredIdentificationRequest oDeclaredIdentificationRequest = new DeclaredIdentificationRequest();
	
			oDeclaredIdentificationRequest.setPath(info.getFilePath());
			oDeclaredIdentificationRequest.setIdentifiedComponentId(newComponentId);
			oDeclaredIdentificationRequest.setIdentifiedVersionId(newVersionId);
			oDeclaredIdentificationRequest.setIdentifiedUsageLevel(UsageLevel.SNIPPET);
			oDeclaredIdentificationRequest.setIdentifiedLicenseInfo(identifiedLicenseInfo);
			
			svc.addDeclaredIdentification(targetProjectId, "/" + info.getFilePath(), oDeclaredIdentificationRequest);
			
		// Exception
		} else {
			log.error("Match Type is not in CODE_MATCH, STRING_MATCH, PATTERN_MATCH:" + matchType);
			return false;
		}
		return true;
	}
	

	protected HashMap<String, List<ProtexIdentificationInfo>> getIdentificationInfoList(String projectId, HashMap<String, String> licenseLabelMap, HashMap<String, String> componentVersionLabelMap, PrintStream out) {
		HashMap<String, List<ProtexIdentificationInfo>> identificationInfoFiles = svc.getIdentificationInfoList(projectId);
		// when empty project (no pending/identify list) 
		if (identificationInfoFiles == null)
			return null; 
		
		for (Map.Entry<String, List<ProtexIdentificationInfo>> entrySet : identificationInfoFiles.entrySet()) {
			String filePath = entrySet.getKey();
			out.println("  > Creating info: " + filePath + "");
			
			for (ProtexIdentificationInfo info : identificationInfoFiles.get(filePath)) {
				
				// build summary map.
				if (!"".equals(ObjectUtils.toString(info.getLicense()))) {
					// Update License label map
					if (!licenseLabelMap.containsKey(info.getLicense())) {
						licenseLabelMap.put(info.getLicense(), this.getLicenseIDByName(info.getLicense()));
					}	
				}
				
				// Update component version label map
				String componentId = null;
				String versionId = null; 

				ProtexIdentificationInfo compVer = this.getComponentIDAndVersionIDWithNames(info.getComponent(), info.getVersion());
				// labal map has mapping info.
				if (compVer != null) {
					componentId = compVer.getComponentID();
					versionId = compVer.getVersionID();
				// else, query
				} else {
					componentId = this.getComponentIDByName(info.getComponent());
					// String search => search comp Id in local
					if (componentId == null) {
						if (ProtexIdentificationInfo.STRING_SEARCH.equals(info.getDiscoveryType())) {
							componentId = this.getLocalComponentId(projectId, info.getComponent(), licenseLabelMap.get(info.getLicense()), info.getLicense());
						} else {
							componentId = this.getComponentIDByNameAndVersionName(info.getComponent(), info.getVersion());
							if (componentId == null) {
								componentId = this.getComponentIDByNameAndLicenseIDAndVersionName(info.getComponent(), licenseLabelMap.get(info.getLicense()), info.getVersion());	
							}
						}	
					}
					versionId = this.getComponentVersionIDByComponentInfoAndVersionName(componentId, info.getComponent(), info.getVersion());
				}
				
				// Update component version label map
				// couldn't find component ID ... then skip
				if (componentId == null) { // || versionId == null) {
					log.info("cannot find component:" + info.getComponent() + "/version:" + info.getVersion() + "/license:" + licenseLabelMap.get(info.getLicense()));
				} else {
					String key = info.getComponent() + "#" + info.getVersion();					
					String value = componentId + "#" + versionId;
					if (!componentVersionLabelMap.containsKey(key)) {
						if (!"#".equals(key)) {
							componentVersionLabelMap.put(key, value);
						}
//if (value.endsWith("null") && !key.endsWith("specified")) {
//	System.out.println(value);
//}
					}
				}				
				
				
			}
			
		}
		
		return identificationInfoFiles;
	}

	
	
	/////////////////////////////////////////////////
	// License, Component, Version DB
	/////////////////////////////////////////////////
	protected String getLicenseIDByName(String licenseName) {
		if (licenseLabelMap.containsKey(licenseName)) {
			return licenseLabelMap.get(licenseName);
		} else {
			try {
				GlobalLicense license  = svc.getLicenseAPI().getLicenseByName(licenseName);
				licenseLabelMap.put(licenseName, license.getLicenseId());
				
				return license.getLicenseId();
			} catch (SdkFault e) {
				log.error(e);
				return null;
			}
		}
	}
	
	protected String getComponentIDByName(String componentName) {
		if (componentMap.containsKey(componentName)) {
			return componentMap.get(componentName);
		} else {
			try {
				StandardComponent standardComponent = svc.getStandardComponentAPI().getStandardComponentByName(componentName);
				componentMap.put(componentName, standardComponent.getComponentId());
				return standardComponent.getComponentId();
			} catch (SdkFault e) {
				try {
					CustomComponent customComponent = svc.getCustomComponentAPI().getCustomComponentByName(componentName);
					componentMap.put(componentName, customComponent.getComponentId());
					return customComponent.getComponentId();	
				} catch (SdkFault e1) {
					log.error("standardComponent: " + e.getMessage() + ", customComponent: " + e1.getMessage());
					componentMap.put(componentName, null);
					return null;
				}
			}
		}
	}
	
	protected String getComponentIDByNameAndVersionName(String componentName, String versionName) {
		log.error("Cannot find component if by component name");
		return null;
	}
	
	protected String getComponentIDByNameAndLicenseIDAndVersionName(String componentName, String licenseId, String versionName) {
		log.error("Cannot find component if by component name and version name");
		return null;
	}
	
	protected ProtexIdentificationInfo getComponentIDAndVersionIDWithNames(String componentName, String versionName) {
		ProtexIdentificationInfo pinfo = new ProtexIdentificationInfo();
		
		String key = componentName + "#" + versionName;
		if (componentVersionlabelMap.containsKey(key)) {
			String label = componentVersionlabelMap.get(key);
			if (label == null)
				return null;
			
			// separate as a function
			String[] items = StringUtils.split(label, "#");
			pinfo.setComponentID(items[0]);
			pinfo.setVersionID(items[1]);
			
			// check component id valid?
			String dbComponentName = this.getComponentIDByName(componentName);
			if (!ObjectUtils.toString(pinfo.getComponentID()).equals(dbComponentName)) {
				// cache
				componentVersionlabelMap.put(key, null);
				return null;
			}
			return pinfo;
		}

		ComponentVersion compVer;
		try {
			compVer = svc.getComponentVersionAPI().getComponentVersionByName(componentName, versionName);
		} catch (SdkFault e) {
			log.error(e.getMessage());
			//log.error("Cannot find IDs by component: " + componentName + ", version: " + versionName);
			// cache 
			if (e.getMessage().contains("not found")) {
				componentVersionlabelMap.put(key, null);
			}
			return null;
		}
		
		componentVersionlabelMap.put(key, compVer.getComponentId() + "#" + compVer.getVersionId());
		pinfo.setComponentID(compVer.getComponentId());
		pinfo.setVersionID(compVer.getVersionId());
		
		return pinfo;
	}

	protected String getLocalComponentId(String projectID, String componentName, String licenseID, String licenseName) {
		String key = projectID + "|" + componentName;
		if (localComponentNameMap.containsKey(key)) {
			return localComponentNameMap.get(key);
		}
		
		try {
			LocalComponentRequest localComponentRequest = new LocalComponentRequest();
	        localComponentRequest.setContextProjectId(projectID);
	        localComponentRequest.setName(componentName);
	        localComponentRequest.setLicenseText(licenseName.getBytes());
	        localComponentRequest.setBasedOnLicenseId(licenseID);
	        String componentID = svc.getLocalComponentAPI().createLocalComponent(localComponentRequest);
	        localComponentNameMap.put(key, componentID);	        
	        
	        return componentID;
	        
		} catch (SdkFault e) {
			log.warn("createLocalComponent() failed: " + e.getMessage());
			return null;
		}
	}
	
	protected String getComponentVersionIDByComponentInfoAndVersionName(String componentId, String componentName, String componentVersionName) {
		if ("Unspecified".equals(componentVersionName)) {
			return "unspecified";
		}
		
		// find component name
		ProtexIdentificationInfo pinfo = this.getComponentIDAndVersionIDWithNames(componentName, componentVersionName);
		if (pinfo == null) {
			return null;
		} else {
			return pinfo.getVersionID();
		}
	}

//	// TODO - Local DB에서 긁어오도록 준비??!!!
//	public String getLicenseIDByName(String licenceName) {
//		return "";
////		try {
////			GlobalLicense license  = ProtexSDKAPIService.licenseAPI.getLicenseById(licenceName);
////			return license.getLicenseId();
////		} catch (SdkFault e) {
////			log.warn(e);
////		}
////		
////		return null;
//	}
	

}
