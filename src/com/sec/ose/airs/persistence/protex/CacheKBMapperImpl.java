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
package com.sec.ose.airs.persistence.protex;

import java.util.HashMap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ibatis.exceptions.TooManyResultsException;
import org.apache.ibatis.session.SqlSession;
import org.apache.ibatis.session.SqlSessionFactory;

import com.sec.ose.airs.domain.autoidentify.ProtexIdentificationInfo;

/**
 * 
 * 
 * @author ytaek.kim
 */
public class CacheKBMapperImpl implements CacheKBMapper {
	private static Log log = LogFactory.getLog(CacheKBMapperImpl.class);
	
	SqlSessionFactory factory = DBSessionFactory.getCacheKBSessionInstance();
	
	@Override
	public String getComponentIDByName(String componentName) {
		SqlSession session = factory.openSession(true);
		
		String result = null;
		
		try {
			result = session.selectOne("getComponentIDByName", componentName);
		} catch (TooManyResultsException e) {
			log.info(e.getMessage());
			return null;
		} finally {
			session.close();
		}
		
		return result;
	}

	@Override
	public String getComponentVersionIDByComponentIDAndVersionName(String componentId,
			String componentVersionName) {
		SqlSession session = factory.openSession(true);
		String result;
		
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("componentId", componentId);
		map.put("componentVersionName", componentVersionName);
		
		try {
			result = session.selectOne("getComponentVersionIDByComponentIDAndVersionName", map);
		} catch (TooManyResultsException e) {
			log.info(e.getMessage());
			return null;
		} finally {
			session.close();
		}
		
		return result;
	}

	@Override
	public String getLicenseIDByName(String licenseName) {
		SqlSession session = factory.openSession(true);
		
		String result;
		
		try {
			result = session.selectOne("getLicenseIDByName", licenseName);
		} finally {
			session.close();
		}

		return result;
	}

	@Override
	public String getLicenseNameByID(String licenseId) {
		SqlSession session = factory.openSession(true);
		
		String result;
		
		try {
			result = session.selectOne("getLicenseNameByID", licenseId);
		} finally {
			session.close();
		}
		
		return result;
	}

	@Override
	public String getComponentIDByNameAndLicenseIDAndVersionName(String componentName, String licenseId, String versionName) {
		SqlSession session = factory.openSession(true);
		String result;
		
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("componentName", componentName);
		map.put("licenseId", licenseId);
		map.put("versionName", versionName);
		
		try {
			result = session.selectOne("getComponentIDByNameAndLicenseIDAndVersionName", map);
		} catch (TooManyResultsException e) {
			log.info(e.getMessage());
			return null;
		} finally {
			session.close();
		}
		
		return result;
	}

	@Override
	public String getComponentIDByNameAndVersionName(String componentName, String versionName) {
		SqlSession session = factory.openSession(true);
		String result;
		
		HashMap<String, String> map = new HashMap<String, String>();
		map.put("componentName", componentName);
		map.put("versionName", versionName);
		
		try {
			result = session.selectOne("getComponentIDByNameAndVersionName", map);
		} catch (TooManyResultsException e) {
			log.info(e.getMessage());
			return null;
		} finally {
			session.close();
		}
		
		return result;
	}
	
	@Override
	public ProtexIdentificationInfo getComponentIDAndVersionIDWithNames(String componentName, String versionName) {
		
		SqlSession session = factory.openSession(true);
		ProtexIdentificationInfo result = null;
		HashMap<String, Object> map = new HashMap<String, Object>();
		
		map.put("componentName", componentName);
		map.put("versionName", versionName);
		
		try {
			result = session.selectOne("getComponentIDAndVersionIDWithNames", map);
		} catch (TooManyResultsException e) {
			log.info(e.getMessage());
			return null;
		} finally {
			session.close();
		}
		
		return result;
	}

	@Override
	public void insertComponent(String componentID, String componentName) {
		SqlSession session = factory.openSession(true);
		HashMap<String, Object> map = new HashMap<String, Object>();
		
		map.put("componentID", componentID);
		map.put("componentName", componentName);
		
		try {
			session.insert("insertComponent", map);
		} finally {
			session.close();
		}
	}

	@Override
	public void insertComponentVersion(String componentID,
			String componentName, String versionID, String versionName) {
		SqlSession session = factory.openSession(true);
		HashMap<String, Object> map = new HashMap<String, Object>();
		
		map.put("componentID", componentID);
		map.put("componentName", componentName);
		map.put("versionID", versionID);
		map.put("versionName", versionName);
		
		try {
			session.insert("insertComponentVersion", map);
		} finally {
			session.close();
		}
	}

	@Override
	public void insertLicense(String licenseID, String licenseName) {
		SqlSession session = factory.openSession(true);
		HashMap<String, Object> map = new HashMap<String, Object>();
		
		map.put("licenseID", licenseID);
		map.put("licenseName", licenseName);
		
		try {
			session.insert("insertLicense", map);
		} finally {
			session.close();
		}
	}

	@Override
	public ProtexIdentificationInfo getComponentVersionNamesWithIDs(String componentID, String versionID) {
		
		SqlSession session = factory.openSession(true);
		ProtexIdentificationInfo result = null;
		HashMap<String, Object> map = new HashMap<String, Object>();
		
		map.put("componentID", componentID);
		map.put("versionID", versionID);
		
		try {
			result = session.selectOne("getComponentVersionNamesWithIDs", map);
		} catch (TooManyResultsException e) {
			log.info(e.getMessage());
			return null;
		} finally {
			session.close();
		}
		
		return result;
	}
}
