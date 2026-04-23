"""
AudioSteg – Steganalysis Module
===============================
Provides anomaly detection for WAV files, including LSB ratio, chi-square
analysis, and metadata chunk detection to estimate suspicion levels.
"""

import os
import wave
import struct
import numpy as np
from typing import Dict, List, Any

class AudioAnalyzer:
    """Performs statistical and structural analysis on WAV audio to detect steganography."""

    @staticmethod
    def analyze(filepath: str) -> Dict[str, Any]:
        """Run a full analysis suite on the given WAV file.
        
        Returns:
            A dictionary containing the analysis report and an overall suspicion score.
        """
        report = {
            "filename": os.path.basename(filepath),
            "file_size_bytes": os.path.getsize(filepath),
            "suspicion_score": 0.0,
            "verdict": "Low Suspicion",
            "findings": [],
            "stats": {}
        }

        try:
            # 1. Structural Analysis (Metadata/RIFF)
            meta_findings = AudioAnalyzer._analyze_metadata(filepath)
            report["findings"].extend(meta_findings["alerts"])
            report["suspicion_score"] += meta_findings["score"]

            # 2. Statistical Analysis (LSB)
            with wave.open(filepath, "rb") as wf:
                params = {
                    "nchannels": wf.getnchannels(),
                    "sampwidth": wf.getsampwidth(),
                    "framerate": wf.getframerate(),
                    "nframes": wf.getnframes(),
                }
                
                if params["sampwidth"] != 2:
                    report["findings"].append({
                        "type": "error",
                        "message": f"Unsupported sample width: {params['sampwidth'] * 8}-bit. Only 16-bit PCM supported."
                    })
                    return report

                raw = wf.readframes(params["nframes"])
                samples = np.frombuffer(raw, dtype=np.int16)
                
                report["stats"]["duration_sec"] = round(params["nframes"] / params["framerate"], 2)
                report["stats"]["sample_rate"] = params["framerate"]
                report["stats"]["channels"] = params["nchannels"]
                report["stats"]["total_samples"] = len(samples)

                # LSB Ratio
                lsb_findings = AudioAnalyzer._analyze_lsb(samples)
                report["findings"].extend(lsb_findings["alerts"])
                report["suspicion_score"] += lsb_findings["score"]
                report["stats"]["lsb_ratio"] = lsb_findings["ratio"]
                report["stats"]["chi_square_p_value"] = lsb_findings["chi_square_p"]

        except Exception as e:
            report["findings"].append({
                "type": "error",
                "message": f"Analysis failed during processing: {str(e)}"
            })

        # Cap score at 100
        score = min(max(report["suspicion_score"], 0.0), 100.0)
        report["suspicion_score"] = round(score, 1)

        # Verdict
        if score > 75:
            report["verdict"] = "High Suspicion"
        elif score > 35:
            report["verdict"] = "Medium Suspicion"
        else:
            report["verdict"] = "Low Suspicion"

        return report

    @staticmethod
    def _analyze_metadata(filepath: str) -> Dict[str, Any]:
        """Check for non-standard or known stego chunks in RIFF."""
        score = 0.0
        alerts = []
        standard_chunks = {b"fmt ", b"data", b"LIST", b"fact", b"id3 ", b"bext"}
        
        try:
            with open(filepath, "rb") as f:
                header = f.read(12)
                if len(header) < 12 or header[:4] != b"RIFF" or header[8:12] != b"WAVE":
                    return {"score": 0.0, "alerts": [{"type": "error", "message": "Invalid WAV header"}]}
                
                while True:
                    chunk_id = f.read(4)
                    if not chunk_id or len(chunk_id) < 4:
                        break
                    
                    size_data = f.read(4)
                    if not size_data or len(size_data) < 4:
                        break
                    
                    chunk_size = struct.unpack("<I", size_data)[0]
                    
                    if chunk_id == b"steg":
                        score += 100.0
                        alerts.append({
                            "type": "critical",
                            "message": f"Found known AudioSteg 'steg' chunk ({chunk_size} bytes)"
                        })
                    elif chunk_id not in standard_chunks:
                        # Unknown non-standard chunk
                        score += 40.0
                        # Try to decode for display safely
                        display_id = ''.join(chr(b) if 32 <= b <= 126 else '?' for b in chunk_id)
                        alerts.append({
                            "type": "warning",
                            "message": f"Found non-standard RIFF chunk '{display_id}' ({chunk_size} bytes)"
                        })
                        
                    f.seek(chunk_size + (chunk_size % 2), 1)
        except Exception as e:
             alerts.append({"type": "error", "message": f"Metadata parsing error: {e}"})

        return {"score": score, "alerts": alerts}

    @staticmethod
    def _analyze_lsb(samples: np.ndarray) -> Dict[str, Any]:
        """Perform statistical analysis on the LSBs."""
        score = 0.0
        alerts = []
        
        # 1. LSB Ratio
        lsbs = samples & 1
        num_ones = np.count_nonzero(lsbs)
        total = len(lsbs)
        
        if total == 0:
            return {"score": 0, "alerts": [], "ratio": 0, "chi_square_p": 1.0}
            
        ratio = num_ones / total
        
        # Normal audio often has LSBs closer to 0 (since small amplitudes are common and 0 is favored in silence)
        # Random data has exactly 0.5 ratio. 
        # If the ratio is extremely close to 0.5, it is suspicious.
        diff_from_half = abs(ratio - 0.5)
        
        if diff_from_half < 0.001:
            score += 50.0
            alerts.append({
                "type": "warning",
                "message": f"LSB distribution is perfectly uniform (ratio={ratio:.5f}), typical of encrypted payload."
            })
        elif diff_from_half < 0.01:
            score += 20.0
            alerts.append({
                "type": "info",
                "message": f"LSB distribution is highly uniform (ratio={ratio:.5f})."
            })

        # 2. Chi-Square Test for sequential embedding
        # We test the frequency of Pairs of Values (PoVs).
        # In sequential LSB embedding, values `2k` and `2k+1` tend to equalise in frequency.
        # To keep it fast, we take a sample of the first 100,000 samples.
        sample_size = min(total, 100000)
        sub_samples = samples[:sample_size]
        
        # Count frequencies of values
        unique, counts = np.unique(sub_samples, return_counts=True)
        freq_dict = dict(zip(unique, counts))
        
        chi_square_stat = 0.0
        degrees_of_freedom = 0
        
        # Iterate over pairs (2k, 2k+1)
        # We only check pairs where at least one value exists
        pairs_checked = 0
        for val in unique:
            if val % 2 != 0:
                continue # Only start at 2k
            
            count_even = freq_dict.get(val, 0)
            count_odd = freq_dict.get(val + 1, 0)
            
            expected = (count_even + count_odd) / 2
            if expected > 5:  # Standard chi-square rule of thumb
                chi_square_stat += ((count_even - expected)**2) / expected
                chi_square_stat += ((count_odd - expected)**2) / expected
                degrees_of_freedom += 1
                pairs_checked += 1
                
        # Approximate p-value conversion (simple thresholding for this tool without scipy dependency)
        # A small chi-square statistic means the frequencies are VERY similar (expected in stego)
        # We flag it if the statistic is suspiciously low for the degrees of freedom
        # Mean of chi-square distribution is degrees_of_freedom. 
        # If stat is much lower than dof, it's artificially uniform (stego signature).
        
        p_value_estimate = 1.0
        if degrees_of_freedom > 10:
            ratio_chi_dof = chi_square_stat / degrees_of_freedom
            if ratio_chi_dof < 0.8:
                score += 80.0
                alerts.append({
                    "type": "critical",
                    "message": "Chi-Square Test indicates high likelihood of Sequential LSB Steganography."
                })
                p_value_estimate = 0.01
            elif ratio_chi_dof < 0.9:
                score += 40.0
                alerts.append({
                    "type": "warning",
                    "message": "Chi-Square Test shows statistical anomalies in value pairs."
                })
                p_value_estimate = 0.05
            else:
                p_value_estimate = 0.5
                
        return {
            "score": score, 
            "alerts": alerts, 
            "ratio": round(ratio, 5), 
            "chi_square_p": p_value_estimate
        }
