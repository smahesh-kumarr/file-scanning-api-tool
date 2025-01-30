import axios from 'axios';
import FormData from 'form-data';
import fs from 'fs';
import path from 'path';
import config from '../config.js';

class ThreatScanService {
    constructor() {
        this.virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;
        this.virusTotalApiUrl = 'https://www.virustotal.com/api/v3';
        this.urlscanApiKey = process.env.URLSCAN_API_KEY;
        this.urlscanApiUrl = 'https://urlscan.io/api/v1';
        
        // Configure axios defaults for VirusTotal
        this.vtAxios = axios.create({
            baseURL: this.virusTotalApiUrl,
            headers: {
                'x-apikey': this.virusTotalApiKey
            }
        });

        // Debug log
        console.log('ThreatScanService initialized with VirusTotal API key:', this.virusTotalApiKey ? 'Present' : 'Missing');
    }

    async scanUrl(url) {
        try {
            console.log('Starting URL scan for:', url);
            
            if (!this.virusTotalApiKey) {
                throw new Error('VirusTotal API key is missing. Please check your environment variables.');
            }

            const [vtResult, urlscanResult] = await Promise.allSettled([
                this.scanWithVirusTotal(url),
                this.scanWithUrlscan(url)
            ]);

            console.log('Scan results:', {
                virusTotal: vtResult.status === 'fulfilled' ? 'Success' : 'Failed',
                urlscan: urlscanResult.status === 'fulfilled' ? 'Success' : 'Failed'
            });

            if (vtResult.status === 'rejected') {
                console.error('VirusTotal scan error:', vtResult.reason);
            }

            if (urlscanResult.status === 'rejected') {
                console.error('Urlscan.io scan error:', urlscanResult.reason);
            }

            // Handle partial failures
            const results = {
                virusTotal: vtResult.status === 'fulfilled' ? vtResult.value : null,
                urlscan: urlscanResult.status === 'fulfilled' ? urlscanResult.value : null
            };

            const aggregatedResults = this.aggregateResults(results);
            console.log('Aggregated results:', aggregatedResults);
            return aggregatedResults;

        } catch (error) {
            console.error('Error in scanUrl:', error);
            console.error('Error details:', {
                message: error.message,
                response: error.response?.data,
                stack: error.stack
            });
            throw error;
        }
    }

    async scanWithVirusTotal(url) {
        try {
            console.log('Scanning with VirusTotal:', url);
            
            // Step 1: Submit URL for scanning
            const scanResponse = await this.vtAxios.post('/urls', new URLSearchParams({
                url: url
            }));

            console.log('VirusTotal scan submitted:', scanResponse.data);
            const analysisId = scanResponse.data.data.id;

            // Step 2: Wait for analysis to complete with retries
            let retries = 5;
            while (retries > 0) {
                console.log(`Checking analysis status (${retries} retries left)`);
                const analysisResponse = await this.vtAxios.get(`/analyses/${analysisId}`);
                const status = analysisResponse.data.data.attributes.status;
                console.log('Analysis status:', status);

                if (status === 'completed') {
                    // Get the full URL report
                    const urlId = btoa(url).replace(/=/g, '');
                    const reportResponse = await this.vtAxios.get(`/urls/${urlId}`);
                    console.log('VirusTotal scan completed successfully');
                    return reportResponse.data.data.attributes.last_analysis_results;
                }

                if (status === 'failed') {
                    throw new Error('VirusTotal analysis failed');
                }

                // Wait before retrying
                await new Promise(resolve => setTimeout(resolve, 2000));
                retries--;
            }

            throw new Error('Analysis timed out');
        } catch (error) {
            console.error('VirusTotal scan error:', {
                message: error.message,
                response: error.response?.data,
                stack: error.stack
            });
            throw error;
        }
    }

    async scanWithUrlscan(url) {
        try {
            console.log('Scanning with urlscan.io:', url);
            
            // Submit URL for scanning
            const submitResponse = await axios.post('https://urlscan.io/api/v1/scan/', {
                url: url,
                visibility: "public"
            }, {
                headers: {
                    'API-Key': this.urlscanApiKey,
                    'Content-Type': 'application/json'
                }
            });

            const uuid = submitResponse.data.uuid;
            console.log('Urlscan scan submitted, UUID:', uuid);

            // Poll for results (urlscan.io takes time to process)
            let resultResponse = null;
            let attempts = 0;
            const maxAttempts = 10;

            while (attempts < maxAttempts) {
                try {
                    await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds between attempts
                    resultResponse = await axios.get(`https://urlscan.io/api/v1/result/${uuid}/`, {
                        headers: {
                            'API-Key': this.urlscanApiKey
                        }
                    });
                    break; // If we get here, we have results
                } catch (error) {
                    if (error.response?.status === 404) {
                        console.log(`Results not ready yet, attempt ${attempts + 1} of ${maxAttempts}`);
                        attempts++;
                        if (attempts === maxAttempts) {
                            throw new Error('Scan results took too long to process. Please try again.');
                        }
                    } else {
                        throw error; // Other errors should be handled normally
                    }
                }
            }

            if (!resultResponse) {
                throw new Error('Failed to get scan results');
            }

            return {
                provider: 'urlscan.io',
                result: resultResponse.data,
                verdict: resultResponse.data.verdicts,
                score: resultResponse.data.score || 0,
                scanId: uuid,
                scanUrl: `https://urlscan.io/result/${uuid}/`
            };
        } catch (error) {
            console.error('Error in urlscan.io scan:', error.response?.data || error.message);
            throw new Error(error.response?.data?.description || error.message);
        }
    }

    async scanFile(file) {
        try {
            console.log('Starting file scan for:', file.path);
            const vtResult = await this.scanFileWithVirusTotal(file);
            console.log('VirusTotal file scan completed:', vtResult);
            return this.processVirusTotalFileResult(vtResult);
        } catch (error) {
            console.error('Error scanning file:', error);
            console.error('Error details:', {
                message: error.message,
                response: error.response?.data,
                stack: error.stack
            });
            throw new Error('Failed to scan file');
        }
    }

    async scanIp(ip) {
        try {
            console.log('Starting IP scan for:', ip);
            const vtResult = await this.scanIpWithVirusTotal(ip);
            console.log('VirusTotal IP scan completed:', vtResult);
            return this.processVirusTotalIpResult(vtResult);
        } catch (error) {
            console.error('Error scanning IP:', error);
            console.error('Error details:', {
                message: error.message,
                response: error.response?.data,
                stack: error.stack
            });
            throw new Error('Failed to scan IP');
        }
    }

    async scanFileWithVirusTotal(file) {
        try {
            console.log('Scanning file with VirusTotal:', file.path);
            const formData = new FormData();
            formData.append('apikey', this.virusTotalApiKey);
            formData.append('file', fs.createReadStream(file.path));

            // Step 1: Upload file
            const uploadResponse = await axios.post(`${this.virusTotalApiUrl}/file/scan`, 
                formData,
                { headers: formData.getHeaders() }
            );

            console.log('VirusTotal file uploaded:', uploadResponse.data);

            // Step 2: Get scan results
            const resultResponse = await axios.get(`${this.virusTotalApiUrl}/file/report`, {
                params: {
                    apikey: this.virusTotalApiKey,
                    resource: uploadResponse.data.scan_id
                }
            });

            console.log('VirusTotal file scan results:', resultResponse.data);
            return resultResponse.data;
        } catch (error) {
            console.error('VirusTotal file scan error:', {
                message: error.message,
                response: error.response?.data,
                stack: error.stack
            });
            throw error;
        }
    }

    async scanIpWithVirusTotal(ip) {
        try {
            console.log('Scanning IP with VirusTotal:', ip);
            const response = await axios.get(`${this.virusTotalApiUrl}/ip-address/report`, {
                params: {
                    apikey: this.virusTotalApiKey,
                    ip: ip
                }
            });

            console.log('VirusTotal IP scan results:', response.data);
            return response.data;
        } catch (error) {
            console.error('VirusTotal IP scan error:', {
                message: error.message,
                response: error.response?.data,
                stack: error.stack
            });
            throw error;
        }
    }

    aggregateResults(results) {
        console.log('Aggregating results:', results);
        const threats = [];
        let status = 'safe';
        let score = 100;

        // Process VirusTotal results
        if (results.virusTotal) {
            const maliciousCount = Object.values(results.virusTotal).filter(
                result => result.category === 'malicious'
            ).length;

            const totalEngines = Object.keys(results.virusTotal).length;

            if (maliciousCount > 0) {
                status = maliciousCount > 2 ? 'dangerous' : 'suspicious';
                score -= (maliciousCount / totalEngines) * 100;
                threats.push(`${maliciousCount} security vendors flagged this as malicious`);
            }
        }

        // Process urlscan.io results
        if (results.urlscan) {
            if (results.urlscan.verdict && results.urlscan.verdict.length > 0) {
                const verdict = results.urlscan.verdict[0];
                if (verdict.result === 'malicious') {
                    status = 'dangerous';
                    score -= 50;
                    threats.push(`Urlscan.io flagged this as malicious: ${verdict.reason}`);
                } else if (verdict.result === 'suspicious') {
                    status = 'suspicious';
                    score -= 25;
                    threats.push(`Urlscan.io flagged this as suspicious: ${verdict.reason}`);
                }
            }
        }

        console.log('Aggregated results:', {
            status,
            score: Math.max(0, Math.round(score)),
            threats,
            lastScanned: new Date().toISOString(),
            details: {
                virusTotal: results.virusTotal ? {
                    maliciousCount: Object.values(results.virusTotal).filter(r => r.category === 'malicious').length,
                    totalEngines: Object.keys(results.virusTotal).length,
                    engineResults: results.virusTotal
                } : null,
                urlscan: results.urlscan ? {
                    verdict: results.urlscan.verdict,
                    score: results.urlscan.score,
                    scanId: results.urlscan.scanId
                } : null
            }
        });
        return {
            status,
            score: Math.max(0, Math.round(score)),
            threats,
            lastScanned: new Date().toISOString(),
            details: {
                virusTotal: results.virusTotal ? {
                    maliciousCount: Object.values(results.virusTotal).filter(r => r.category === 'malicious').length,
                    totalEngines: Object.keys(results.virusTotal).length,
                    engineResults: results.virusTotal
                } : null,
                urlscan: results.urlscan ? {
                    verdict: results.urlscan.verdict,
                    score: results.urlscan.score,
                    scanId: results.urlscan.scanId
                } : null
            }
        };
    }

    processVirusTotalFileResult(vtResult) {
        console.log('Processing VirusTotal file result:', vtResult);
        const threats = [];
        let status = 'safe';
        let score = 100;

        if (vtResult.positives > 0) {
            status = vtResult.positives > 2 ? 'dangerous' : 'suspicious';
            score -= (vtResult.positives / vtResult.total) * 100;
            threats.push(`${vtResult.positives} security vendors flagged this file as malicious`);
        }

        console.log('Processed VirusTotal file result:', {
            status,
            score: Math.max(0, Math.round(score)),
            threats,
            lastScanned: new Date().toISOString(),
            details: {
                virusTotal: {
                    positives: vtResult.positives,
                    total: vtResult.total,
                    scanDate: vtResult.scan_date,
                    sha256: vtResult.sha256,
                    md5: vtResult.md5
                }
            }
        });
        return {
            status,
            score: Math.max(0, Math.round(score)),
            threats,
            lastScanned: new Date().toISOString(),
            details: {
                virusTotal: {
                    positives: vtResult.positives,
                    total: vtResult.total,
                    scanDate: vtResult.scan_date,
                    sha256: vtResult.sha256,
                    md5: vtResult.md5
                }
            }
        };
    }

    processVirusTotalIpResult(vtResult) {
        console.log('Processing VirusTotal IP result:', vtResult);
        const threats = [];
        let status = 'safe';
        let score = 100;

        if (vtResult.detected_urls && vtResult.detected_urls.length > 0) {
            const maliciousUrls = vtResult.detected_urls.filter(url => url.positives > 0);
            if (maliciousUrls.length > 0) {
                status = maliciousUrls.length > 2 ? 'dangerous' : 'suspicious';
                score -= (maliciousUrls.length / vtResult.detected_urls.length) * 100;
                threats.push(`${maliciousUrls.length} malicious URLs associated with this IP`);
            }
        }

        console.log('Processed VirusTotal IP result:', {
            status,
            score: Math.max(0, Math.round(score)),
            threats,
            lastScanned: new Date().toISOString(),
            details: {
                virusTotal: {
                    detectedUrls: vtResult.detected_urls,
                    country: vtResult.country,
                    owner: vtResult.as_owner
                }
            }
        });
        return {
            status,
            score: Math.max(0, Math.round(score)),
            threats,
            lastScanned: new Date().toISOString(),
            details: {
                virusTotal: {
                    detectedUrls: vtResult.detected_urls,
                    country: vtResult.country,
                    owner: vtResult.as_owner
                }
            }
        };
    }
}

export default new ThreatScanService();
