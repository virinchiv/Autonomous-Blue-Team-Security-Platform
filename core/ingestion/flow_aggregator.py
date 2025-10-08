import numpy as np
import time
import pandas as pd
from .parser import LogParser

class FlowAggregator:
    def __init__(self, flow_timeout=60):
        self.flow_cache = {}
        self.flow_timeout = flow_timeout
        self.completed_flows = []
    
    def _create_flow_key(self, log: dict):
        ip1,ip2 = sorted((log['id.orig_h'], log['id.resp_h']))
        port1, port2 = sorted((log['id.orig_p'], log['id.resp_p']))
        return f"{ip1}-{port1}-{ip2}-{port2}-{log['proto']}"

    def process_log(self, log: dict):
        flow_key = self._create_flow_key(log)
        if flow_key not in self.flow_cache:
            self.flow_cache[flow_key] = {
                'start_time': log['ts'],
                'last_time': log['ts'],
                'packets': [],
                'orig_h': log['id.orig_h'], # Store original direction
                'resp_h': log['id.resp_h'],
            }
        flow = self.flow_cache[flow_key]

        if flow['packets']:
            iat = log['ts'] - flow['last_time']
            if 'iats' not in flow:
                flow['iats'] = []
            flow['iats'].append(iat)
        
        flow['last_time'] = log['ts']
        flow['packets'].append(log)
        
        if log.get('duration', 0) > 0 or log.get('conn_state') in ['SF', 'REJ', 'RSTO', 'RSTR']:
            self._finalize_flow(flow_key)
        
    def check_for_timeouts(self):
        now = time.time()
        timed_out_keys = [
            key for key, flow in self.flow_cache.items()
            if (now - flow['last_time']) > self.flow_timeout
        ]
        for key in timed_out_keys:
            self._finalize_flow(key)
        return self.completed_flows
    
    def _finalize_flow(self, flow_key):
        """Calculates features for a completed flow and moves it out of the cache."""
        if flow_key not in self.flow_cache:
            return
        flow_data = self.flow_cache.pop(flow_key)
        features = self._calculate_features(flow_data)
        self.completed_flows.append(features)
    
    def _calculate_features(self, flow: dict):
        """Calculates the Tier 1 features from the aggregated flow data."""
        fwd_packets = [p for p in flow['packets'] if p['id.orig_h'] == flow['orig_h']]
        bwd_packets = [p for p in flow['packets'] if p['id.orig_h'] == flow['resp_h']]
        fwd_bytes = sum(p['orig_bytes'] for p in fwd_packets)
        bwd_bytes = sum(p['resp_bytes'] for p in bwd_packets)
        total_bytes = fwd_bytes + bwd_bytes
        total_packets = len(flow['packets'])
        all_packet_sizes = [p['orig_bytes'] for p in fwd_packets] + [p['resp_bytes'] for p in bwd_packets]
        
        duration = flow['last_time'] - flow['start_time']
        summary_duration = max(p['duration'] for p in flow['packets'])
        duration = max(duration, summary_duration)
        if duration == 0: duration = 1e-6

        final_state = flow['packets'][-1]['conn_state']
        fin_count = 1 if 'F' in final_state else 0
        psh_count = 1 if final_state == 'SF' else 0 

        return {
            'Idle Mean': np.mean(flow.get('iats', [0])),
            'PSH Flag Count': psh_count,
            'Average Packet Size': np.mean(all_packet_sizes) if all_packet_sizes else 0,
            'Max Packet Length': max(all_packet_sizes) if all_packet_sizes else 0,
            'Total Fwd Packets': len(fwd_packets),
            'Total Backward Packets': len(bwd_packets),
            'Total Length of Fwd Packets': fwd_bytes,
            'Bwd Packets/s': len(bwd_packets) / duration,
            'FIN Flag Count': fin_count,
            'Destination Port': flow['packets'][0]['id.resp_p'],
            'Flow Bytes/s': total_bytes / duration
        }