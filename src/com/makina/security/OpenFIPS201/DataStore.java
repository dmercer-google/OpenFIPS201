package com.makina.security.OpenFIPS201;

import javacard.framework.JCSystem;

public final class DataStore {
	private static boolean initialized = false;
	private static PIVDataObject dataStore;
	private static PIVKeyObject keyStore;
	
	private DataStore() {};

	public static void init() {
		if(!initialized) {
			JCSystem.beginTransaction();
			dataStore = new PIVDataObject((byte)0xFF, (byte)0, (byte)0);
			keyStore = new PIVKeyObjectSYM((byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF);
			initialized = true;
			JCSystem.commitTransaction();
		}
	}
	
	public static PIVDataObject getDataStore() {
		return dataStore;
	}
	
	public static PIVKeyObject getKeyStore() {
		return keyStore;
	}
	
    /**
     * Searches for a data object within the local data store
     * @param id The data object to find
     */
    public static PIVDataObject findDataObject(byte id) {
        PIVDataObject data = dataStore;
        // Traverse the linked list
        while (data != null) {
            if (data.match(id)) {
                return data;
            };
            data = (PIVDataObject)data.nextObject;
        }
        return null;
    }
    
    
    public static boolean keyExists(byte id) {
	    return findKey(id) != null;	       
    }
    
    public static PIVKeyObject findKey(byte id) {
        PIVKeyObject key = keyStore;

        // Traverse the linked list
        while (key != null) {
            if (key.match(id)) break;
            key = (PIVKeyObject)key.nextObject;
        }
        return key;	       
    }
    
    public static void addKey(PIVKeyObject key, boolean allowDuplicates) {
    	
    }
    
    public static void removeKey(byte id) {
    	
    }
}
