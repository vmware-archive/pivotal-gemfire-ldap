/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package io.pivotal.gemfire.ldap;

import org.apache.geode.cache.*;
import org.apache.geode.internal.cache.GemFireCacheImpl;
import org.apache.geode.internal.cache.InternalRegionArguments;
import org.apache.geode.internal.logging.LogService;
import org.apache.logging.log4j.Logger;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

public class GemFireShiroCache<K, V> implements Cache<K, V> {

    private static final Logger logger = LogService.getLogger();
    private static final Object classLock = new Object();

    private static final String REGION_PREFIX = "_ldap_";
    private Region<K, V> region = null;
    private String name;

    private GemFireShiroCacheManager manager;

    public GemFireShiroCache(String name, GemFireShiroCacheManager manager) {
        this.name = REGION_PREFIX + name;
        this.manager = manager;
    }

    private Region<K, V> getRegion() throws CacheException {
        if (region == null) {
            // If the cache isn't instantiated don't cache - fall through
            GemFireCacheImpl gemFireCache = (GemFireCacheImpl) CacheFactory.getAnyInstance();
            if (gemFireCache != null) {
                //Create the LDAP caching region
                atomicCreateRegion(gemFireCache);
            }
        }
        return region;
    }

    private void atomicCreateRegion(GemFireCacheImpl gemFireCache) throws CacheException {
        synchronized (classLock) {
            region = gemFireCache.getRegion(name);
            if (region == null) {
                logger.info("Creating LDAP region for cache name " + name);
                AttributesFactory attributesFactory = new AttributesFactory();
                attributesFactory.setScope(Scope.DISTRIBUTED_ACK);
                attributesFactory.setDataPolicy(DataPolicy.REPLICATE);
                if (manager.getEntryTimeToLiveSeconds() > 0) {
                    attributesFactory.setStatisticsEnabled(true);
                    attributesFactory.setEntryTimeToLive(new ExpirationAttributes(manager.getEntryTimeToLiveSeconds(), ExpirationAction.DESTROY));
                } else if (manager.getEntryIdleTimeoutSeconds() > 0) {
                    attributesFactory.setEntryIdleTimeout(new ExpirationAttributes(manager.getEntryIdleTimeoutSeconds(), ExpirationAction.DESTROY));
                }
                RegionAttributes regionAttributes = attributesFactory.create();
                InternalRegionArguments internalRegionArguments = new InternalRegionArguments();
                internalRegionArguments.setIsUsedForMetaRegion(true);
                try {
                    region = gemFireCache.createVMRegion(name, regionAttributes, internalRegionArguments);
                } catch (Exception e) {
                    throw new CacheException(e);
                }
            }
        }
    }

    /**
     * Returns the Cached value stored under the specified {@code key} or
     * {@code null} if there is no Cache entry for that {@code key}.
     *
     * @param key the key that the value was previous added with
     * @return the cached object or {@code null} if there is no entry for the specified {@code key}
     * @throws CacheException if there is a problem accessing the underlying cache system
     */
    @Override
    public V get(K key) throws CacheException {
        Region<K, V> region = getRegion();
        if (region != null) {
            V value = region.get(key);
            if (logger.isDebugEnabled()) {
                logger.debug("get(" + key + ") = " + value);
            }
            return value;
        }
        return null;
    }

    /**
     * Adds a Cache entry.
     *
     * @param key   the key used to identify the object being stored.
     * @param value the value to be stored in the cache.
     * @return the previous value associated with the given {@code key} or {@code null} if there was previous value
     * @throws CacheException if there is a problem accessing the underlying cache system
     */
    @Override
    public V put(K key, V value) throws CacheException {
        Region<K, V> region = getRegion();
        if (region != null) {
            if (logger.isDebugEnabled()) {
                logger.debug("put(" + key + ", " + value + " )");
            }
            return region.put(key, value);
        }
        return null;
    }

    /**
     * Remove the cache entry corresponding to the specified key.
     *
     * @param key the key of the entry to be removed.
     * @return the previous value associated with the given {@code key} or {@code null} if there was previous value
     * @throws CacheException if there is a problem accessing the underlying cache system
     */
    @Override
    public V remove(K key) throws CacheException {
        Region<K, V> region = getRegion();
        if (region != null) {
            V value = region.remove(key);
            if (logger.isDebugEnabled()) {
                logger.debug("remove (" + key + ") = " + value);
            }
            return value;
        }
        return null;
    }

    /**
     * Clear all entries from the cache.
     *
     * @throws CacheException if there is a problem accessing the underlying cache system
     */
    @Override
    public void clear() throws CacheException {
        Region<K, V> region = getRegion();
        if (region != null) {
            region.clear();
        }
    }

    /**
     * Returns the number of entries in the cache.
     *
     * @return the number of entries in the cache.
     */
    @Override
    public int size() {
        Region<K, V> region = getRegion();
        if (region != null) {
            region.size();
        }
        return 0;
    }

    /**
     * Returns a view of all the keys for entries contained in this cache.
     *
     * @return a view of all the keys for entries contained in this cache.
     */
    @Override
    public Set<K> keys() {
        Region<K, V> region = getRegion();
        if (region != null) {
            return region.keySet();
        }
        return Collections.emptySet();
    }

    /**
     * Returns a view of all of the values contained in this cache.
     *
     * @return a view of all of the values contained in this cache.
     */
    @Override
    public Collection<V> values() {
        Region<K, V> region = getRegion();
        if (region != null) {
            return region.values();
        }
        return Collections.emptySet();
    }
}
