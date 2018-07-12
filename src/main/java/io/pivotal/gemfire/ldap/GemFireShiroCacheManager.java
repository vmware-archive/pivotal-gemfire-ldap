/*
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

package io.pivotal.gemfire.ldap;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.util.Destroyable;

import java.util.concurrent.ConcurrentHashMap;

public class GemFireShiroCacheManager implements CacheManager, Destroyable {

    private final ConcurrentHashMap<String, Cache> cacheMap = new ConcurrentHashMap<>();
    private int entryTimeToLiveSeconds = -1;
    private int entryIdleTimeoutSeconds = -1;

    public int getEntryTimeToLiveSeconds() {
        return entryTimeToLiveSeconds;
    }

    public void setEntryTimeToLiveSeconds(int entryTimeToLiveSeconds) {
        this.entryTimeToLiveSeconds = entryTimeToLiveSeconds;
    }

    public int getEntryIdleTimeoutSeconds() {
        return entryIdleTimeoutSeconds;
    }

    public void setEntryIdleTimeoutSeconds(int entryIdleTimeoutSeconds) {
        this.entryIdleTimeoutSeconds = entryIdleTimeoutSeconds;
    }

    /**
     * Acquires the cache with the specified <code>name</code>.  If a cache does not yet exist with that name, a new one
     * will be created with that name and returned.
     *
     * @param name the name of the cache to acquire.
     * @return the Cache with the given name
     * @throws CacheException if there is an error acquiring the Cache instance.
     */
    @Override
    public <K, V> Cache<K, V> getCache(String name) throws CacheException {
        Cache<K, V> returnValue = cacheMap.get(name);
        if (returnValue == null) {
            returnValue = createCacheAtomic(name);
        }
        return returnValue;
    }

    private <K, V> Cache<K, V> createCacheAtomic(String name) {
        Cache<K, V> returnValue;
        synchronized (cacheMap) {
            returnValue = cacheMap.get(name);
            if (returnValue == null) {
                returnValue = new GemFireShiroCache<K, V>(name, this);
                cacheMap.put(name, returnValue);
            }
        }
        return returnValue;
    }

    /**
     * Called when this object is being destroyed, allowing any necessary cleanup of internal resources.
     *
     * @throws Exception if an exception occurs during object destruction.
     */
    @Override
    public void destroy() throws Exception {

    }
}
