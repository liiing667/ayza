/*
 * Copyright 2019 Thunderberry.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.altindag.ssl.trustmanager;

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.exception.GenericIOException;
import nl.altindag.ssl.exception.GenericKeyStoreException;
import nl.altindag.ssl.model.TrustManagerParameters;
import nl.altindag.ssl.util.CertificateUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.lang.reflect.Method;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static nl.altindag.ssl.TestConstants.DER_LOCATION;
import static nl.altindag.ssl.TestConstants.HOME_DIRECTORY;
import static nl.altindag.ssl.TestConstants.PEM_LOCATION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
class InflatableX509ExtendedTrustManagerShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[]{'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystore/";

    @Test
    void initiallyBeEmpty() {
        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();

        X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
        assertThat(acceptedIssuers).isEmpty();
    }

    @Test
    void initiallyContainDummyTrustManager() {
        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();

        X509ExtendedTrustManager innerTrustManager = trustManager.getInnerTrustManager();
        assertThat(innerTrustManager).isInstanceOf(DummyX509ExtendedTrustManager.class);
    }

    @Test
    void addNewlyTrustedCertificates() throws KeyStoreException {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustedCerts).hasSizeGreaterThan(0);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();
        trustManager.addCertificates(Arrays.asList(trustedCerts));

        assertThat(trustManager.getAcceptedIssuers()).containsExactly(trustedCerts);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");
    }

    @Test
    void trustManagerWillNotBeReloadedIfNullIsProvidedAsNewCertificate() {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();
        assertThat(trustManager.getInnerTrustManager()).isInstanceOf(DummyX509ExtendedTrustManager.class);

        trustManager.addCertificates(null);
        assertThat(trustManager.getInnerTrustManager()).isInstanceOf(DummyX509ExtendedTrustManager.class);

        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(logCaptor.getLogs()).containsExactly("No trust store path has been specified. Creating an empty in-memory trust store");
    }

    @Test
    void trustManagerWillNotBeReloadedIfEmptyListIsProvidedAsNewCertificate() {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();
        assertThat(trustManager.getInnerTrustManager()).isInstanceOf(DummyX509ExtendedTrustManager.class);

        trustManager.addCertificates(Collections.emptyList());
        assertThat(trustManager.getInnerTrustManager()).isInstanceOf(DummyX509ExtendedTrustManager.class);

        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThat(logCaptor.getLogs()).containsExactly("No trust store path has been specified. Creating an empty in-memory trust store");
    }

    @Test
    void rollbackTheInMemoryTrustStoreWhenAddingTheCertificateFails() throws KeyStoreException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustedCerts).hasSizeGreaterThan(0);

        KeyStore mockedTrustStore = Mockito.mock(KeyStore.class);
        when(mockedTrustStore.getType()).thenReturn(KeyStore.getDefaultType());
        when(mockedTrustStore.getProvider()).thenReturn(KeyStore.getInstance(KeyStore.getDefaultType()).getProvider());
        doThrow(new KeyStoreException()).when(mockedTrustStore).setCertificateEntry(anyString(), any(Certificate.class));

        try (MockedStatic<KeyStoreUtils> mockedStatic = Mockito.mockStatic(KeyStoreUtils.class, invocationOnMock -> {
            Method method = invocationOnMock.getMethod();
            if ((method.getName().equals("createKeyStore") && method.getParameters().length == 0)
                    || method.getName().equals("copyKeyStore")) {
                return mockedTrustStore;
            } else {
                return invocationOnMock.callRealMethod();
            }
        })) {
            InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();

            assertThatThrownBy(() -> trustManager.addCertificates(Arrays.asList(trustedCerts)))
                    .isInstanceOf(GenericKeyStoreException.class)
                    .hasCauseInstanceOf(KeyStoreException.class);

            assertThat(trustManager.getAcceptedIssuers()).isEmpty();
            assertThat(trustManager.getInnerTrustManager()).isInstanceOf(DummyX509ExtendedTrustManager.class);
        }
    }

    @Test
    void addNewlyTrustedCertificatesToExistingTrustStore() throws KeyStoreException, IOException {
        Path destinationDirectory = Paths.get(HOME_DIRECTORY, "hakky54-ssl");
        Path trustStoreDestination = destinationDirectory.resolve("inflatable-truststore.p12");
        Files.createDirectories(destinationDirectory);
        assertThat(Files.exists(destinationDirectory)).isTrue();

        KeyStore existingTrustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);
        KeyStoreUtils.write(trustStoreDestination, existingTrustStore, TRUSTSTORE_PASSWORD);
        assertThat(Files.exists(trustStoreDestination)).isTrue();

        assertThat(Files.exists(trustStoreDestination)).isTrue();
        X509Certificate[] existingTrustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(existingTrustStore);
        assertThat(existingTrustedCerts).hasSize(1);

        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustedCerts).hasSizeGreaterThan(0);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, TRUSTSTORE_PASSWORD, "PKCS12", null);
        assertThat(trustManager.getInnerTrustManager()).isNotInstanceOf(DummyX509ExtendedTrustManager.class);
        trustManager.addCertificates(Arrays.asList(trustedCerts));

        X509Certificate[] combinedTrustedCertificates = Stream.concat(Arrays.stream(existingTrustedCerts), Arrays.stream(trustedCerts)).toArray(X509Certificate[]::new);
        assertThat(trustManager.getAcceptedIssuers()).containsExactlyInAnyOrder(combinedTrustedCertificates);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");

        Files.deleteIfExists(trustStoreDestination);
        Files.deleteIfExists(destinationDirectory);
    }

    @Test
    void notCreateTrustManagerIfExistingTrustStoreDoesNotContainTrustedCertificates() throws KeyStoreException, IOException {
        Path destinationDirectory = Paths.get(HOME_DIRECTORY, "hakky54-ssl");
        Path trustStoreDestination = destinationDirectory.resolve("inflatable-truststore.p12");
        Files.createDirectories(destinationDirectory);
        assertThat(Files.exists(destinationDirectory)).isTrue();

        KeyStore existingTrustStore = KeyStoreUtils.createKeyStore("PKCS12", TRUSTSTORE_PASSWORD);
        KeyStoreUtils.write(trustStoreDestination, existingTrustStore, TRUSTSTORE_PASSWORD);
        assertThat(Files.exists(trustStoreDestination)).isTrue();

        assertThat(Files.exists(trustStoreDestination)).isTrue();
        X509Certificate[] existingTrustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(existingTrustStore);
        assertThat(existingTrustedCerts).isEmpty();

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, TRUSTSTORE_PASSWORD, "PKCS12", null);
        assertThat(trustManager.getInnerTrustManager()).isInstanceOf(DummyX509ExtendedTrustManager.class);

        Files.deleteIfExists(trustStoreDestination);
        Files.deleteIfExists(destinationDirectory);
    }

    @Test
    void addNewlyTrustedCertificatesToANewTrustStoreInANonExistingDirectory() throws KeyStoreException, IOException {
        Path destinationDirectory = Paths.get(HOME_DIRECTORY, "hakky54-ssl");
        Path trustStoreDestination = destinationDirectory.resolve("inflatable-truststore.p12");
        assertThat(Files.notExists(destinationDirectory)).isTrue();

        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustedCerts).hasSizeGreaterThan(0);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, TRUSTSTORE_PASSWORD, "PKCS12", trustManagerParameters -> true);
        trustManager.addCertificates(Arrays.asList(trustedCerts));

        X509Certificate[] combinedTrustedCertificates = Arrays.stream(trustedCerts).toArray(X509Certificate[]::new);
        assertThat(trustManager.getAcceptedIssuers()).containsExactlyInAnyOrder(combinedTrustedCertificates);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");

        assertThat(Files.exists(destinationDirectory)).isTrue();
        assertThat(Files.exists(trustStoreDestination)).isTrue();

        Files.deleteIfExists(trustStoreDestination);
        Files.deleteIfExists(destinationDirectory);
    }

    @Test
    void notUseExistingProvidedTrustStorePathIfTrustStoreTypeIsMissing() throws KeyStoreException, IOException {
        Path trustStoreDestination = Paths.get(HOME_DIRECTORY, "inflatable-truststore.p12");
        assertThat(Files.exists(trustStoreDestination)).isFalse();

        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustedCerts).hasSizeGreaterThan(0);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, TRUSTSTORE_PASSWORD, null, null);
        trustManager.addCertificates(Arrays.asList(trustedCerts));

        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");
        assertThat(Files.exists(trustStoreDestination)).isTrue();

        Files.delete(trustStoreDestination);
    }

    @Test
    void addNewlyTrustedCertificatesWhileAlsoWritingToAKeyStoreOnTheFileSystem() throws KeyStoreException, IOException {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustedCerts).hasSizeGreaterThan(0);

        Path destinationDirectory = Paths.get(HOME_DIRECTORY, "hakky54-ssl");
        Path trustStoreDestination = destinationDirectory.resolve("inflatable-truststore.p12");
        Files.createDirectories(destinationDirectory);
        assertThat(Files.exists(destinationDirectory)).isTrue();

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, "secret".toCharArray(), "PKCS12", trustManagerParameters -> true);
        trustManager.addCertificates(Arrays.asList(trustedCerts));

        assertThat(trustManager.getAcceptedIssuers()).containsExactly(trustedCerts);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");

        assertThat(Files.exists(trustStoreDestination)).isTrue();
        KeyStore inflatedTrustStore = KeyStoreUtils.loadKeyStore(trustStoreDestination, "secret".toCharArray(), "PKCS12");
        assertThat(KeyStoreTestUtils.getTrustedX509Certificates(inflatedTrustStore)).containsExactly(trustedCerts);

        Files.deleteIfExists(trustStoreDestination);
        Files.deleteIfExists(destinationDirectory);
    }

    @Test
    void addOnlyOnceNewlyTrustedCertificates() throws KeyStoreException {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustedCerts).hasSizeGreaterThan(0);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(null, null, null, trustManagerParameters -> true);
        trustManager.addCertificates(Arrays.asList(trustedCerts));

        assertThat(trustManager.getAcceptedIssuers()).containsExactly(trustedCerts);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");
        logCaptor.clearLogs();

        trustManager.addCertificates(Arrays.asList(trustedCerts));
        assertThat(logCaptor.getInfoLogs()).isEmpty();
    }

    @Test
    void callPredicateAndAddCertificatesIfTrusted() throws KeyStoreException, IOException, CertificateException {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate notYetTrustedCert = KeyStoreTestUtils.getTrustedX509Certificates(trustStore)[0];

        Path trustStoreDestination = Paths.get(HOME_DIRECTORY, "inflatable-truststore.p12");
        assertThat(Files.exists(trustStoreDestination)).isFalse();

        AtomicBoolean shouldTrust = new AtomicBoolean(false);
        Predicate<TrustManagerParameters> predicate = trustManagerParameters -> shouldTrust.get();
        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, "secret".toCharArray(), "PKCS12", predicate);

        assertThatThrownBy(() -> trustManager.checkServerTrusted(new X509Certificate[]{notYetTrustedCert}, "RSA")).isInstanceOf(CertificateException.class);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        shouldTrust.set(true);
        trustManager.checkServerTrusted(new X509Certificate[] {notYetTrustedCert}, "RSA");

        assertThat(trustManager.getAcceptedIssuers()).containsExactly(notYetTrustedCert);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");

        assertThat(Files.exists(trustStoreDestination)).isTrue();
        KeyStore inflatedTrustStore = KeyStoreUtils.loadKeyStore(trustStoreDestination, "secret".toCharArray(), "PKCS12");
        assertThat(KeyStoreTestUtils.getTrustedX509Certificates(inflatedTrustStore)).containsExactly(notYetTrustedCert);

        Files.delete(trustStoreDestination);
    }

    @Test
    void notAddCertificateIfInnerTrustManagerHasTrustedTheNewCertificateFromADifferentThread() throws KeyStoreException, CertificateException {
        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        doThrow(new CertificateException("KABOOOM!"))
                .doNothing()
                .when(innerTrustManager)
                .checkServerTrusted(any(), anyString());

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate notYetTrustedCert = KeyStoreTestUtils.getTrustedX509Certificates(trustStore)[0];

        AtomicBoolean shouldTrust = new AtomicBoolean(true);
        Predicate<TrustManagerParameters> predicate = trustManagerParameters -> shouldTrust.get();
        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(null, null, null, predicate);
        trustManager.setTrustManager(innerTrustManager);

        trustManager.checkServerTrusted(new X509Certificate[] {notYetTrustedCert}, "RSA");
        assertThat(trustManager.getInnerTrustManager()).isEqualTo(innerTrustManager);
    }

    @Test
    void onlyCallPredicateOnceWhenConcurrentThreadsCheckForTheSameCertificate() throws KeyStoreException, IOException, InterruptedException, ExecutionException {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate notYetTrustedCert = KeyStoreTestUtils.getTrustedX509Certificates(trustStore)[0];

        Path trustStoreDestination = Paths.get(HOME_DIRECTORY, "inflatable-truststore.p12");
        assertThat(Files.exists(trustStoreDestination)).isFalse();

        AtomicBoolean shouldTrust = new AtomicBoolean(true);
        Predicate<TrustManagerParameters> predicate = trustManagerParameters -> {
            // Only the first call to the predicate will return true
            if (shouldTrust.getAndSet(false)) {
                return true;
            }
            // Following calls (if any, but we only expect one) will throw
            throw new IllegalStateException("Predicate should only be called once");
        };
        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, "secret".toCharArray(), "PKCS12", predicate);

        int threadCount = Runtime.getRuntime().availableProcessors();
        ExecutorService exec = Executors.newFixedThreadPool(threadCount);
        var futureList = new ArrayList<Future<?>>();
        IntStream.of(threadCount).forEach( i -> {
            futureList.add(exec.submit(() -> {
                try {
                    trustManager.checkServerTrusted(new X509Certificate[] {notYetTrustedCert}, "RSA");
                } catch (CertificateException e) {
                    throw new RuntimeException(e);
                }
            }));
        });
        for (Future<?> future : futureList) {
            future.get();
        }

        assertThat(trustManager.getAcceptedIssuers()).containsExactly(notYetTrustedCert);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");

        assertThat(Files.exists(trustStoreDestination)).isTrue();
        KeyStore inflatedTrustStore = KeyStoreUtils.loadKeyStore(trustStoreDestination, "secret".toCharArray(), "PKCS12");
        assertThat(KeyStoreTestUtils.getTrustedX509Certificates(inflatedTrustStore)).containsExactly(notYetTrustedCert);

        Files.delete(trustStoreDestination);
        exec.shutdownNow();
    }

    @Test
    void onlyCallPredicateOnce() throws KeyStoreException, IOException, InterruptedException, ExecutionException, CertificateException {
        LogCaptor logCaptor = LogCaptor.forClass(InflatableX509ExtendedTrustManager.class);
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate notYetTrustedCert = KeyStoreTestUtils.getTrustedX509Certificates(trustStore)[0];

        Path trustStoreDestination = Paths.get(HOME_DIRECTORY, "inflatable-truststore.p12");
        assertThat(Files.exists(trustStoreDestination)).isFalse();

        AtomicBoolean shouldTrust = new AtomicBoolean(true);
        Predicate<TrustManagerParameters> predicate = trustManagerParameters -> {
            // Only the first call to the predicate will return true
            if (shouldTrust.getAndSet(false)) {
                return true;
            }
            // Following calls (if any, but we only expect one) will throw
            throw new IllegalStateException("Predicate should only be called once");
        };
        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, "secret".toCharArray(), "PKCS12", predicate);

        trustManager.checkServerTrusted(new X509Certificate[]{notYetTrustedCert}, "RSA");
        trustManager.checkServerTrusted(new X509Certificate[]{notYetTrustedCert}, "RSA");

        assertThat(trustManager.getAcceptedIssuers()).containsExactly(notYetTrustedCert);
        assertThat(logCaptor.getInfoLogs()).containsExactly("Added certificate for [cn=googlecom_o=google-llc_l=mountain-view_st=california_c=us]");

        assertThat(Files.exists(trustStoreDestination)).isTrue();
        KeyStore inflatedTrustStore = KeyStoreUtils.loadKeyStore(trustStoreDestination, "secret".toCharArray(), "PKCS12");
        assertThat(KeyStoreTestUtils.getTrustedX509Certificates(inflatedTrustStore)).containsExactly(notYetTrustedCert);

        Files.delete(trustStoreDestination);
    }

    @Test
    void checkServerTrusted() throws CertificateException {
        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        X509Certificate[] chain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();
        trustManager.setTrustManager(innerTrustManager);

        trustManager.checkServerTrusted(chain, authType);

        verify(innerTrustManager, times(1)).checkServerTrusted(chain, authType);
    }

    @Test
    void checkServerTrustedWithSocket() throws CertificateException {
        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        X509Certificate[] chain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        Socket socket = mock(Socket.class);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();
        trustManager.setTrustManager(innerTrustManager);

        trustManager.checkServerTrusted(chain, authType, socket);

        verify(innerTrustManager, times(1)).checkServerTrusted(chain, authType, socket);
    }

    @Test
    void checkServerTrustedWithSSLEngine() throws CertificateException {
        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        X509Certificate[] chain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        SSLEngine sslEngine = mock(SSLEngine.class);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();
        trustManager.setTrustManager(innerTrustManager);

        trustManager.checkServerTrusted(chain, authType, sslEngine);

        verify(innerTrustManager, times(1)).checkServerTrusted(chain, authType, sslEngine);
    }

    @Test
    void checkClientTrusted() throws CertificateException {
        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        X509Certificate[] chain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();
        trustManager.setTrustManager(innerTrustManager);

        trustManager.checkClientTrusted(chain, authType);

        verify(innerTrustManager, times(1)).checkClientTrusted(chain, authType);
    }

    @Test
    void checkClientTrustedWithSocket() throws CertificateException {
        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        X509Certificate[] chain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        Socket socket = mock(Socket.class);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();
        trustManager.setTrustManager(innerTrustManager);

        trustManager.checkClientTrusted(chain, authType, socket);

        verify(innerTrustManager, times(1)).checkClientTrusted(chain, authType, socket);
    }

    @Test
    void checkClientTrustedWithSSLEngine() throws CertificateException {
        X509ExtendedTrustManager innerTrustManager = mock(X509ExtendedTrustManager.class);
        X509Certificate[] chain = new X509Certificate[]{mock(X509Certificate.class)};
        String authType = "RSA";
        SSLEngine sslEngine = mock(SSLEngine.class);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();
        trustManager.setTrustManager(innerTrustManager);

        trustManager.checkClientTrusted(chain, authType, sslEngine);

        verify(innerTrustManager, times(1)).checkClientTrusted(chain, authType, sslEngine);
    }

    @Test
    void rollbackTheTrustUpdateAndKeepTheExistingTrustStoreWhenCallingGenerateAliasFails() throws KeyStoreException, IOException {
        KeyStore trustStore = spy(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD));

        List<X509Certificate> notYetTrustedCerts = CertificateUtils.loadCertificate(DER_LOCATION + "digicert.cer")
                .stream()
                .filter(X509Certificate.class::isInstance)
                .map(X509Certificate.class::cast)
                .collect(Collectors.toList());

        assertThat(notYetTrustedCerts).hasSize(1);

        Path destinationDirectory = Paths.get(HOME_DIRECTORY, "hakky54-ssl");
        Path trustStoreDestination = destinationDirectory.resolve("inflatable-truststore.p12");
        Files.createDirectories(destinationDirectory);
        assertThat(Files.exists(destinationDirectory)).isTrue();

        KeyStoreUtils.write(trustStoreDestination, trustStore, TRUSTSTORE_PASSWORD);
        assertThat(Files.exists(trustStoreDestination)).isTrue();

        try(MockedStatic<KeyStoreUtils> mockedStatic = mockStatic(KeyStoreUtils.class, invocationOnMock -> {
            Method method = invocationOnMock.getMethod();
            if ("loadKeyStore".equals(method.getName())) {
                return trustStore;
            } else if ("copyKeyStore".equals(method.getName())) {
                KeyStore copiedTrustStore = spy((KeyStore) invocationOnMock.callRealMethod());
                doThrow(new KeyStoreException("KABOOM!")).when(copiedTrustStore).containsAlias(anyString());
                return copiedTrustStore;
            } else {
                return invocationOnMock.callRealMethod();
            }
        })) {
            InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, "secret".toCharArray(), "PKCS12", trustManagerParameters -> true);
            assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

            assertThatThrownBy(() -> trustManager.addCertificates(notYetTrustedCerts))
                    .isInstanceOf(GenericKeyStoreException.class)
                    .hasCauseInstanceOf(KeyStoreException.class);

            assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
            KeyStore reloadedTrustStore = KeyStoreUtils.loadKeyStore(trustStoreDestination, "secret".toCharArray(), "PKCS12");
            assertThat(KeyStoreTestUtils.getTrustedX509Certificates(reloadedTrustStore)).hasSize(1);
        } finally {
            Files.deleteIfExists(trustStoreDestination);
            Files.deleteIfExists(destinationDirectory);
        }
    }

    @Test
    void rollbackTheInMemoryTrustSetAndKeepTheExistingTrustStoreWhenPersistingFails() throws KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);
        List<X509Certificate> newCertificates = CertificateUtils.loadCertificate(DER_LOCATION + "digicert.cer")
                .stream()
                .filter(X509Certificate.class::isInstance)
                .map(X509Certificate.class::cast)
                .collect(Collectors.toList());

        assertThat(trustedCerts).hasSizeGreaterThan(0);
        assertThat(newCertificates).hasSize(1);

        Path destinationDirectory = Paths.get(HOME_DIRECTORY, "hakky54-ssl");
        Path trustStoreDestination = destinationDirectory.resolve("inflatable-truststore.p12");
        Files.createDirectories(destinationDirectory);
        KeyStoreUtils.write(trustStoreDestination, trustStore, TRUSTSTORE_PASSWORD);

        InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, TRUSTSTORE_PASSWORD, "PKCS12", null);
        assertThat(trustManager.getAcceptedIssuers()).containsExactly(trustedCerts);

        try (MockedStatic<KeyStoreUtils> mockedStatic = mockStatic(KeyStoreUtils.class, invocationOnMock -> {
            Method method = invocationOnMock.getMethod();
            if ("writeAtomic".equals(method.getName())) {
                throw new GenericIOException(new IOException("KABOOM!"));
            }
            return invocationOnMock.callRealMethod();
        })) {
            assertThatThrownBy(() -> trustManager.addCertificates(newCertificates))
                    .isInstanceOf(GenericIOException.class);

            assertThat(trustManager.getAcceptedIssuers()).containsExactly(trustedCerts);

            KeyStore reloadedTrustStore = KeyStoreUtils.loadKeyStore(trustStoreDestination, TRUSTSTORE_PASSWORD, "PKCS12");
            assertThat(KeyStoreTestUtils.getTrustedX509Certificates(reloadedTrustStore)).containsExactly(trustedCerts);
        } finally {
            Files.deleteIfExists(trustStoreDestination);
            Files.deleteIfExists(destinationDirectory);
        }
    }

    @Test
    void notLeaveATemporaryFileBehindWhenTheTrustStoreIsPersisted() throws KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        Path destinationDirectory = Paths.get(HOME_DIRECTORY, "hakky54-ssl");
        Path trustStoreDestination = destinationDirectory.resolve("inflatable-truststore.p12");
        Files.createDirectories(destinationDirectory);

        try {
            InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, TRUSTSTORE_PASSWORD, "PKCS12", null);
            trustManager.addCertificates(Arrays.asList(trustedCerts));

            assertThat(Files.exists(trustStoreDestination)).isTrue();
            try (Stream<Path> files = Files.list(destinationDirectory)) {
                assertThat(files).containsExactly(trustStoreDestination);
            }

            KeyStore reloadedTrustStore = KeyStoreUtils.loadKeyStore(trustStoreDestination, TRUSTSTORE_PASSWORD, "PKCS12");
            assertThat(KeyStoreTestUtils.getTrustedX509Certificates(reloadedTrustStore)).containsExactly(trustedCerts);
        } finally {
            Files.deleteIfExists(trustStoreDestination);
            Files.deleteIfExists(destinationDirectory);
        }
    }

    @Test
    void applyTheCompleteTransactionWhenMultipleCertificatesAreAddedAtOnce() throws KeyStoreException, IOException {
        List<X509Certificate> certificates = CertificateUtils.loadCertificate(
                        PEM_LOCATION + "badssl-certificate.pem",
                        PEM_LOCATION + "github-certificate.pem",
                        PEM_LOCATION + "stackexchange.pem")
                .stream()
                .map(X509Certificate.class::cast)
                .collect(Collectors.toList());

        Path destinationDirectory = Paths.get(HOME_DIRECTORY, "hakky54-ssl");
        Path trustStoreDestination = destinationDirectory.resolve("inflatable-truststore.p12");
        Files.createDirectories(destinationDirectory);

        try {
            InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, TRUSTSTORE_PASSWORD, "PKCS12", null);
            trustManager.addCertificates(certificates);

            assertThat(trustManager.getAcceptedIssuers()).containsExactlyInAnyOrderElementsOf(certificates);

            KeyStore reloadedTrustStore = KeyStoreUtils.loadKeyStore(trustStoreDestination, TRUSTSTORE_PASSWORD, "PKCS12");
            assertThat(KeyStoreTestUtils.getTrustedX509Certificates(reloadedTrustStore)).containsExactlyInAnyOrderElementsOf(certificates);
        } finally {
            Files.deleteIfExists(trustStoreDestination);
            Files.deleteIfExists(destinationDirectory);
        }
    }

    @Test
    void returnAconsistentTrustSetWhenCertificatesAreAddedConcurrently() throws KeyStoreException, IOException, InterruptedException, ExecutionException {
        List<X509Certificate> certificates = CertificateUtils.loadCertificate(
                        PEM_LOCATION + "badssl-certificate.pem",
                        PEM_LOCATION + "github-certificate.pem",
                        PEM_LOCATION + "stackexchange.pem")
                .stream()
                .map(X509Certificate.class::cast)
                .collect(Collectors.toList());

        Path destinationDirectory = Paths.get(HOME_DIRECTORY, "hakky54-ssl");
        Path trustStoreDestination = destinationDirectory.resolve("inflatable-truststore.p12");
        Files.createDirectories(destinationDirectory);

        try {
            InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager(trustStoreDestination, TRUSTSTORE_PASSWORD, "PKCS12", null);

            int threadCount = Runtime.getRuntime().availableProcessors();
            ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
            CountDownLatch startLatch = new CountDownLatch(1);
            AtomicReference<Throwable> failure = new AtomicReference<>();

            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < threadCount; i++) {
                X509Certificate certificate = certificates.get(i % certificates.size());
                futures.add(executorService.submit(() -> {
                    try {
                        startLatch.await();
                        trustManager.addCertificates(Collections.singletonList(certificate));
                    } catch (Throwable throwable) {
                        failure.compareAndSet(null, throwable);
                    }
                }));
            }

            startLatch.countDown();
            for (Future<?> future : futures) {
                future.get();
            }
            executorService.shutdownNow();

            assertThat(failure).hasValue(null);
            assertThat(trustManager.getAcceptedIssuers()).containsExactlyInAnyOrderElementsOf(certificates);

            KeyStore reloadedTrustStore = KeyStoreUtils.loadKeyStore(trustStoreDestination, TRUSTSTORE_PASSWORD, "PKCS12");
            assertThat(KeyStoreTestUtils.getTrustedX509Certificates(reloadedTrustStore)).containsExactlyInAnyOrderElementsOf(certificates);
        } finally {
            Files.deleteIfExists(trustStoreDestination);
            Files.deleteIfExists(destinationDirectory);
        }
    }

    @Test
    void notPartiallyUpdateTheTrustSetWhenOneOfTheCertificatesCanNotBeAdded() throws KeyStoreException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);
        List<X509Certificate> newCertificates = CertificateUtils.loadCertificate(DER_LOCATION + "digicert.cer")
                .stream()
                .filter(X509Certificate.class::isInstance)
                .map(X509Certificate.class::cast)
                .collect(Collectors.toList());

        assertThat(newCertificates).hasSize(1);

        KeyStore initialTrustStore = KeyStoreUtils.createKeyStore();
        KeyStore failingTrustStore = spy(KeyStoreUtils.copyKeyStore(initialTrustStore, KeyStoreUtils.DUMMY_PASSWORD.toCharArray()));
        doThrow(new KeyStoreException("KABOOM!"))
                .when(failingTrustStore)
                .setCertificateEntry(anyString(), any(Certificate.class));

        try (MockedStatic<KeyStoreUtils> mockedStatic = Mockito.mockStatic(KeyStoreUtils.class, invocationOnMock -> {
            Method method = invocationOnMock.getMethod();
            if (method.getName().equals("copyKeyStore")) {
                return failingTrustStore;
            }
            return invocationOnMock.callRealMethod();
        })) {
            InflatableX509ExtendedTrustManager trustManager = new InflatableX509ExtendedTrustManager();

            List<X509Certificate> certificatesToAdd = Stream.concat(Arrays.stream(trustedCerts), newCertificates.stream())
                    .collect(Collectors.toList());
            assertThat(certificatesToAdd).hasSizeGreaterThan(1);

            assertThatThrownBy(() -> trustManager.addCertificates(certificatesToAdd))
                    .isInstanceOf(GenericKeyStoreException.class);

            assertThat(trustManager.getAcceptedIssuers()).isEmpty();
            assertThat(trustManager.getInnerTrustManager()).isInstanceOf(DummyX509ExtendedTrustManager.class);
        }
    }

}
