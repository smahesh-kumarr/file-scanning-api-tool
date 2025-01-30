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

            const vtResult = await this.submitToVirusTotal(url);
            const urlscanResult = await this.submitToUrlscan(url);

            const vtScore = vtResult ? this.calculateVirusTotalScore(vtResult) : 100;
            const urlscanScore = urlscanResult ? this.calculateUrlscanScore(urlscanResult) : 100;
            const overallScore = Math.min(vtScore, urlscanScore);

            let status = 'SAFE';
            if (overallScore < 40) status = 'DANGEROUS';
            else if (overallScore < 70) status = 'SUSPICIOUS';

            const threats = [];
            if (vtResult && vtResult.maliciousCount > 0) {
                threats.push(`${vtResult.maliciousCount} security vendors flagged this URL as malicious`);
            }
            if (urlscanResult && urlscanResult.verdictDetails) {
                threats.push(urlscanResult.verdictDetails);
            }

            return {
                status,
                score: overallScore,
                threats,
                details: {
                    virusTotal: vtResult ? {
                        maliciousCount: vtResult.maliciousCount,
                        totalEngines: vtResult.totalEngines,
                        scanId: vtResult.scanId
                    } : null,
                    urlscan: urlscanResult ? {
                        verdict: urlscanResult.verdict,
                        scanUrl: urlscanResult.scanUrl,
                        verdictDetails: urlscanResult.verdictDetails
                    } : null
                }
            };
        } catch (error) {
            console.error('Error in scanUrl:', error);
            throw error;
        }
    }

    async submitToVirusTotal(url) {
        try {
            console.log('Scanning with VirusTotal:', url);
            
            // Check if URL is already in VT database
            const urlId = btoa(url).replace(/=/g, '');
            try {
                const existingReport = await this.vtAxios.get(`/urls/${urlId}`);
                if (existingReport.data.data) {
                    const result = existingReport.data.data.attributes.last_analysis_results;
                    const stats = existingReport.data.data.attributes.last_analysis_stats;
                    return {
                        maliciousCount: stats.malicious,
                        suspiciousCount: stats.suspicious,
                        totalEngines: Object.keys(result).length,
                        categories: existingReport.data.data.attributes.categories || {},
                        lastAnalysisStats: stats,
                        reputation: existingReport.data.data.attributes.reputation || 0
                    };
                }
            } catch (error) {
                if (error.response?.status !== 404) {
                    throw error;
                }
            }

            // If URL not found, submit for scanning
            const scanResponse = await this.vtAxios.post('/urls', `url=${encodeURIComponent(url)}`);
            const analysisId = scanResponse.data.data.id;

            // Poll for results
            let retries = 10;
            while (retries > 0) {
                const analysisResponse = await this.vtAxios.get(`/analyses/${analysisId}`);
                const { status } = analysisResponse.data.data.attributes;

                if (status === 'completed') {
                    const result = analysisResponse.data.data.attributes.results;
                    const stats = analysisResponse.data.data.attributes.stats;
                    return {
                        maliciousCount: stats.malicious,
                        suspiciousCount: stats.suspicious,
                        totalEngines: Object.keys(result).length,
                        categories: analysisResponse.data.data.attributes.categories || {},
                        lastAnalysisStats: stats,
                        reputation: analysisResponse.data.data.attributes.reputation || 0
                    };
                }

                if (status === 'failed') {
                    throw new Error('VirusTotal scan failed');
                }

                retries--;
                await new Promise(resolve => setTimeout(resolve, 2000));
            }

            throw new Error('Scan timeout');
        } catch (error) {
            console.error('Error in VirusTotal scan:', error.response?.data || error.message);
            throw error;
        }
    }

    async submitToUrlscan(url) {
        try {
            console.log('Scanning with urlscan.io:', url);
            
            const scanResponse = await axios.post(
                'https://urlscan.io/api/v1/scan/',
                {
                    url: url,
                    visibility: 'public'
                },
                {
                    headers: {
                        'API-Key': process.env.URLSCAN_API_KEY,
                        'Content-Type': 'application/json'
                    }
                }
            );

            const uuid = scanResponse.data.uuid;
            console.log('Urlscan scan submitted, uuid:', uuid);

            // Poll for results
            let retries = 15;
            while (retries > 0) {
                try {
                    const resultResponse = await axios.get(`https://urlscan.io/api/v1/result/${uuid}/`);
                    
                    // Check if scan is complete
                    if (resultResponse.data.task && resultResponse.data.task.status === 'complete') {
                        const data = resultResponse.data;
                        const malicious = data.verdicts.overall.malicious;
                        const suspicious = this.checkUrlscanSuspiciousIndicators(data);
                        
                        return {
                            verdict: malicious ? 'malicious' : suspicious ? 'suspicious' : 'safe',
                            scanUrl: `https://urlscan.io/result/${uuid}/`,
                            verdictDetails: this.getUrlscanVerdictDetails(data),
                            score: data.score || 0,
                            malicious,
                            suspicious,
                            indicators: {
                                ipRisk: data.verdicts.ipRisk || 0,
                                domainRisk: data.verdicts.domainRisk || 0,
                                totalAlerts: (data.alerts || []).length,
                                securityHeaders: data.headers?.security || [],
                                certificates: data.certificates || []
                            }
                        };
                    }
                } catch (error) {
                    if (error.response?.status !== 404) {
                        throw error;
                    }
                }

                retries--;
                await new Promise(resolve => setTimeout(resolve, 2000));
            }

            throw new Error('Failed to get scan results');
        } catch (error) {
            console.error('Error in urlscan.io scan:', error.response?.data || error.message);
            throw error;
        }
    }

    checkUrlscanSuspiciousIndicators(data) {
        const suspiciousIndicators = [];

        // Check for suspicious TLS/SSL certificates
        if (data.certificates && data.certificates.length > 0) {
            const cert = data.certificates[0];
            if (cert.validFrom && new Date(cert.validFrom) > new Date()) {
                suspiciousIndicators.push('Certificate not yet valid');
            }
            if (cert.validTo && new Date(cert.validTo) < new Date()) {
                suspiciousIndicators.push('Expired certificate');
            }
            if (cert.issuer && cert.issuer.O && cert.issuer.O.toLowerCase().includes('free')) {
                suspiciousIndicators.push('Free SSL certificate');
            }
        }

        // Check for missing security headers
        const expectedHeaders = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection'];
        const missingHeaders = expectedHeaders.filter(header => 
            !data.headers?.security?.some(h => h.toLowerCase().startsWith(header.toLowerCase()))
        );
        if (missingHeaders.length > 0) {
            suspiciousIndicators.push('Missing security headers');
        }

        // Check for suspicious redirects
        if (data.redirects && data.redirects.length > 2) {
            suspiciousIndicators.push('Multiple redirects');
        }

        // Check for suspicious domain age
        if (data.domain && data.domain.registered) {
            const domainAge = new Date() - new Date(data.domain.registered);
            if (domainAge < 30 * 24 * 60 * 60 * 1000) { // Less than 30 days
                suspiciousIndicators.push('Recently registered domain');
            }
        }

        // Check for suspicious technologies
        if (data.technologies) {
            const suspiciousTech = data.technologies.filter(tech => 
                tech.categories.some(cat => 
                    ['advertising', 'tracker', 'suspicious'].includes(cat.toLowerCase())
                )
            );
            if (suspiciousTech.length > 0) {
                suspiciousIndicators.push('Suspicious technologies detected');
            }
        }

        return suspiciousIndicators.length > 0;
    }

    getUrlscanVerdictDetails(data) {
        const details = [];

        if (data.verdicts.overall.malicious) {
            details.push('Malicious indicators detected by urlscan.io');
        }

        const suspiciousIndicators = this.checkUrlscanSuspiciousIndicators(data);
        if (suspiciousIndicators.length > 0) {
            details.push(...suspiciousIndicators);
        }

        if (data.verdicts.overall.score < 0) {
            details.push(`Low trust score: ${data.verdicts.overall.score}`);
        }

        if (data.alerts && data.alerts.length > 0) {
            details.push(`${data.alerts.length} security alerts detected`);
        }

        return details.join('. ');
    }

    calculateVirusTotalScore(result) {
        if (!result) return 100;

        const stats = result.lastAnalysisStats || {};
        const totalScanned = Object.values(stats).reduce((a, b) => a + b, 0);
        
        if (totalScanned === 0) return 100;

        // Calculate weighted score
        let score = 100;
        
        // Heavily penalize malicious findings
        if (stats.malicious > 0) {
            score -= (stats.malicious / totalScanned) * 100;
        }

        // Penalize suspicious findings
        if (stats.suspicious > 0) {
            score -= (stats.suspicious / totalScanned) * 30;
        }

        // Consider reputation score
        if (result.reputation < 0) {
            score += result.reputation;
        }

        return Math.max(0, Math.round(score));
    }

    calculateUrlscanScore(result) {
        if (!result) return 100;

        let score = 100;

        // Penalize based on verdict
        if (result.malicious) {
            score -= 60;
        } else if (result.suspicious) {
            score -= 30;
        }

        // Additional penalties based on indicators
        if (result.indicators) {
            if (result.indicators.ipRisk > 0) {
                score -= result.indicators.ipRisk * 10;
            }
            if (result.indicators.domainRisk > 0) {
                score -= result.indicators.domainRisk * 10;
            }
            if (result.indicators.totalAlerts > 0) {
                score -= result.indicators.totalAlerts * 5;
            }
        }

        return Math.max(0, Math.round(score));
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
