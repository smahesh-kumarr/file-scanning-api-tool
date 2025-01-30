import Threat from '../models/Threat.js';

class ThreatMonitoringService {
    constructor(io) {
        this.io = io;
        this.monitoringInterval = null;
    }

    // Start real-time threat monitoring
    startMonitoring() {
        // Monitor threats every 30 seconds
        this.monitoringInterval = setInterval(async () => {
            try {
                const threats = await this.getActiveThreatsSummary();
                this.io.emit('threats:update', threats);
            } catch (error) {
                console.error('Error in threat monitoring:', error);
            }
        }, 30000);
    }

    // Stop monitoring
    stopMonitoring() {
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
        }
    }

    // Get summary of active threats
    async getActiveThreatsSummary() {
        try {
            const [
                totalThreats,
                severityCounts,
                recentThreats
            ] = await Promise.all([
                Threat.countDocuments({ status: 'ACTIVE' }),
                this.getThreatSeverityCounts(),
                this.getRecentThreats()
            ]);

            return {
                totalActiveThreats: totalThreats,
                severityCounts,
                recentThreats
            };
        } catch (error) {
            console.error('Error getting threat summary:', error);
            throw error;
        }
    }

    // Get count of threats by severity
    async getThreatSeverityCounts() {
        try {
            const counts = await Threat.aggregate([
                { $match: { status: 'ACTIVE' } },
                { $group: { _id: '$severity', count: { $sum: 1 } } }
            ]);

            const severityCounts = {
                CRITICAL: 0,
                HIGH: 0,
                MEDIUM: 0,
                LOW: 0
            };

            counts.forEach(({ _id, count }) => {
                severityCounts[_id] = count;
            });

            return severityCounts;
        } catch (error) {
            console.error('Error getting severity counts:', error);
            throw error;
        }
    }

    // Get recent threats
    async getRecentThreats(limit = 5) {
        try {
            return await Threat.find({ status: 'ACTIVE' })
                .sort({ createdAt: -1 })
                .limit(limit)
                .select('title severity type createdAt');
        } catch (error) {
            console.error('Error getting recent threats:', error);
            throw error;
        }
    }

    // Add a new threat and notify connected clients
    async addThreat(threatData) {
        try {
            const threat = new Threat(threatData);
            await threat.save();
            
            // Get updated summary and notify clients
            const summary = await this.getActiveThreatsSummary();
            this.io.emit('threats:update', summary);
            this.io.emit('threats:new', threat);

            return threat;
        } catch (error) {
            console.error('Error adding threat:', error);
            throw error;
        }
    }

    // Update threat status and notify connected clients
    async updateThreatStatus(threatId, status) {
        try {
            const threat = await Threat.findByIdAndUpdate(
                threatId,
                { status },
                { new: true }
            );

            if (!threat) {
                throw new Error('Threat not found');
            }

            // Get updated summary and notify clients
            const summary = await this.getActiveThreatsSummary();
            this.io.emit('threats:update', summary);
            this.io.emit('threats:statusUpdate', { threatId, status });

            return threat;
        } catch (error) {
            console.error('Error updating threat status:', error);
            throw error;
        }
    }
}

export default ThreatMonitoringService;
