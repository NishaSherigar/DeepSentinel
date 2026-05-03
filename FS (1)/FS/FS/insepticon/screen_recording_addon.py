# =============================================================================
# DeepSentinel — screen_recording_addon.py
# Screen Recording Module
# Captures video clips on critical threat alerts
# =============================================================================

import os
import json
import subprocess
import threading
from datetime import datetime, timedelta
from collections import defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))


class ScreenRecordingManager:
    """Manages screen recording capture for forensic analysis"""
    
    def __init__(self):
        self.recordings_path = os.path.join(ROOT, "data", "videos")
        self.recording_log_path = os.path.join(ROOT, "data", "recording_log.jsonl")
        self.active_recordings = {}
        self.recording_queue = []
        
        os.makedirs(self.recordings_path, exist_ok=True)
    
    def start_recording(self, user_id, hostname, trigger_reason, duration=30, bitrate='2000k'):
        """
        Start screen recording on user's machine
        
        Args:
            user_id: User being monitored
            hostname: Computer hostname/IP
            trigger_reason: Why recording started (CRITICAL alert, suspicious activity, etc)
            duration: Recording length in seconds (default 30s)
            bitrate: Video bitrate (default 2000k = good quality)
        
        Returns:
            {
                'recording_id': str,
                'user_id': str,
                'hostname': str,
                'start_time': str,
                'status': 'REQUESTED' | 'RECORDING' | 'COMPLETED' | 'FAILED'
            }
        """
        
        recording_id = f"rec_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        recording = {
            'recording_id': recording_id,
            'user_id': user_id,
            'hostname': hostname,
            'trigger_reason': trigger_reason,
            'start_time': datetime.now().isoformat(),
            'duration': duration,
            'bitrate': bitrate,
            'status': 'REQUESTED',
            'file_path': os.path.join(self.recordings_path, f"{recording_id}.mp4"),
            'file_size': 0
        }
        
        # Add to active recordings
        self.active_recordings[recording_id] = recording
        
        # Queue for agent to execute
        self.recording_queue.append(recording)
        
        # Log request
        self._log_recording(recording)
        
        return recording
    
    def _execute_recording(self, recording):
        """
        Execute screen recording using ffmpeg or platform-specific tools
        For Windows: Uses ffmpeg or DXVA2
        For Linux: Uses ffmpeg or X11grab
        For macOS: Uses ffmpeg or avfoundation
        """
        
        try:
            recording_id = recording['recording_id']
            user_id = recording['user_id']
            duration = recording['duration']
            file_path = recording['file_path']
            
            # Update status
            recording['status'] = 'RECORDING'
            
            # Try ffmpeg first
            try:
                # Detect OS and build command
                import platform
                os_type = platform.system()
                
                if os_type == 'Windows':
                    # Windows screen recording via ffmpeg + gdigrab
                    cmd = [
                        'ffmpeg',
                        '-f', 'gdigrab',
                        '-framerate', '30',
                        '-i', 'desktop',
                        '-c:v', 'libx264',
                        '-preset', 'ultrafast',
                        '-b:v', recording['bitrate'],
                        '-t', str(duration),
                        '-y',
                        file_path
                    ]
                
                elif os_type == 'Linux':
                    # Linux screen recording via ffmpeg + x11grab
                    cmd = [
                        'ffmpeg',
                        '-f', 'x11grab',
                        '-framerate', '30',
                        '-i', ':0.0',
                        '-c:v', 'libx264',
                        '-preset', 'ultrafast',
                        '-b:v', recording['bitrate'],
                        '-t', str(duration),
                        '-y',
                        file_path
                    ]
                
                elif os_type == 'Darwin':
                    # macOS screen recording
                    cmd = [
                        'ffmpeg',
                        '-f', 'avfoundation',
                        '-framerate', '30',
                        '-i', '1:0',
                        '-c:v', 'libx264',
                        '-preset', 'ultrafast',
                        '-b:v', recording['bitrate'],
                        '-t', str(duration),
                        '-y',
                        file_path
                    ]
                
                else:
                    raise Exception(f"Unsupported OS: {os_type}")
                
                # Execute recording
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                # Wait for completion (blocking)
                process.wait(timeout=duration + 10)
                
                # Check if file was created
                if os.path.exists(file_path):
                    recording['status'] = 'COMPLETED'
                    recording['file_size'] = os.path.getsize(file_path)
                    recording['completed_at'] = datetime.now().isoformat()
                    return True
                else:
                    raise Exception('FFmpeg failed to create video file')
            
            except (FileNotFoundError, Exception) as e:
                # FFmpeg not available or failed - fall back to screenshot approach
                print(f"⚠️ FFmpeg unavailable: {e}, using screenshot fallback")
                return self._execute_screenshot_fallback(recording)
        
        except Exception as e:
            recording['status'] = 'FAILED'
            recording['error'] = str(e)
            return False
        
        finally:
            # Update log
            self._log_recording(recording)
    
    def _execute_screenshot_fallback(self, recording):
        """
        Fallback: Capture screenshots at intervals instead of video
        Creates a tar/zip file of screenshots
        """
        try:
            recording_id = recording['recording_id']
            user_id = recording['user_id']
            duration = recording['duration']
            file_path_base = recording['file_path'].replace('.mp4', '')
            
            # Create screenshot directory
            screenshot_dir = os.path.join(self.recordings_path, f"{recording_id}_screenshots")
            os.makedirs(screenshot_dir, exist_ok=True)
            
            recording['status'] = 'RECORDING'
            recording['method'] = 'SCREENSHOTS'
            
            # Capture screenshot sequence
            import time
            interval = max(1, duration // 10)  # 10 frames total
            frames_captured = 0
            
            for i in range(10):
                try:
                    # Try using PIL/Pillow
                    from PIL import ImageGrab
                    screenshot = ImageGrab.grab()
                    screenshot_path = os.path.join(screenshot_dir, f"frame_{i:03d}.png")
                    screenshot.save(screenshot_path)
                    frames_captured += 1
                except:
                    # Fallback to platform-specific methods
                    pass
                
                if i < 9:
                    time.sleep(interval)
            
            if frames_captured > 0:
                # Create tar file of screenshots
                import tarfile
                tar_path = f"{file_path_base}_screenshots.tar.gz"
                with tarfile.open(tar_path, 'w:gz') as tar:
                    tar.add(screenshot_dir, arcname=recording_id)
                
                recording['status'] = 'COMPLETED'
                recording['file_size'] = os.path.getsize(tar_path)
                recording['frames_captured'] = frames_captured
                recording['completed_at'] = datetime.now().isoformat()
                recording['file_path'] = tar_path
                
                # Clean up screenshot directory
                import shutil
                shutil.rmtree(screenshot_dir)
                
                return True
            else:
                raise Exception('Could not capture any screenshots')
        
        except Exception as e:
            recording['status'] = 'FAILED'
            recording['error'] = str(e)
            return False
        
        finally:
            self._log_recording(recording)
    
    def request_screenshot_to_video(self, user_id, hostname, reason, duration=10):
        """
        Alternative: Request series of screenshots and combine into video
        For systems without ffmpeg
        """
        
        screenshot_id = f"screenvid_{user_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        request = {
            'request_id': screenshot_id,
            'user_id': user_id,
            'hostname': hostname,
            'reason': reason,
            'start_time': datetime.now().isoformat(),
            'duration': duration,
            'interval': 1,  # Screenshot every 1 second
            'total_frames': duration,
            'status': 'REQUESTED'
        }
        
        # Queue for agent
        self.recording_queue.append(request)
        
        return request
    
    def get_recording_status(self, recording_id):
        """Get status of a recording"""
        return self.active_recordings.get(recording_id)
    
    def download_recording(self, recording_id):
        """Get recording file for download"""
        if recording_id in self.active_recordings:
            recording = self.active_recordings[recording_id]
            
            if recording['status'] == 'COMPLETED' and os.path.exists(recording['file_path']):
                return recording['file_path']
        
        return None
    
    def delete_recording(self, recording_id, reason=None):
        """Delete recording (e.g., false positive investigation)"""
        
        if recording_id in self.active_recordings:
            recording = self.active_recordings[recording_id]
            
            # Delete file
            if os.path.exists(recording['file_path']):
                try:
                    os.remove(recording['file_path'])
                except:
                    pass
            
            # Mark as deleted
            recording['deleted_at'] = datetime.now().isoformat()
            recording['deletion_reason'] = reason
            recording['status'] = 'DELETED'
            
            # Log deletion
            self._log_recording(recording)
            
            return True
        
        return False
    
    def list_recordings(self, user_id=None, hours=24):
        """List recent recordings"""
        
        cutoff = datetime.now() - timedelta(hours=hours)
        recordings = []
        
        for rec_id, recording in self.active_recordings.items():
            start = datetime.fromisoformat(recording['start_time'])
            
            if start > cutoff:
                if user_id is None or recording['user_id'] == user_id:
                    recordings.append(recording)
        
        # Sort by start time descending
        recordings.sort(key=lambda x: x['start_time'], reverse=True)
        
        return recordings
    
    def get_storage_stats(self):
        """Get storage usage statistics"""
        
        total_size = 0
        total_count = 0
        
        if os.path.exists(self.recordings_path):
            for file in os.listdir(self.recordings_path):
                file_path = os.path.join(self.recordings_path, file)
                if os.path.isfile(file_path):
                    total_size += os.path.getsize(file_path)
                    total_count += 1
        
        # Convert to readable format
        size_mb = total_size / (1024 * 1024)
        
        return {
            'total_recordings': total_count,
            'total_size_mb': round(size_mb, 2),
            'average_size_mb': round(size_mb / total_count, 2) if total_count > 0 else 0,
            'storage_path': self.recordings_path
        }
    
    def cleanup_old_recordings(self, days=30):
        """Delete recordings older than N days"""
        
        cutoff = datetime.now() - timedelta(days=days)
        deleted = 0
        freed_mb = 0
        
        for rec_id, recording in list(self.active_recordings.items()):
            start = datetime.fromisoformat(recording['start_time'])
            
            if start < cutoff:
                file_path = recording['file_path']
                
                if os.path.exists(file_path):
                    try:
                        freed_mb += os.path.getsize(file_path) / (1024 * 1024)
                        os.remove(file_path)
                        deleted += 1
                        
                        # Remove from active
                        del self.active_recordings[rec_id]
                    except:
                        pass
        
        return {
            'recordings_deleted': deleted,
            'space_freed_mb': round(freed_mb, 2)
        }
    
    def _log_recording(self, recording):
        """Log recording event"""
        try:
            with open(self.recording_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(recording) + '\n')
        except:
            pass
    
    def get_recording_by_trigger(self, trigger_reason):
        """Find recordings by trigger reason"""
        
        recordings = [
            rec for rec in self.active_recordings.values()
            if rec.get('trigger_reason') == trigger_reason
        ]
        
        return recordings
    
    def estimate_storage_needed(self, duration_seconds, bitrate='2000k'):
        """Estimate storage needed for recording"""
        
        # Parse bitrate (e.g., '2000k' = 2000 kilobits/sec)
        bitrate_str = bitrate.lower()
        
        if 'k' in bitrate_str:
            bitrate_kbps = int(bitrate_str.replace('k', ''))
        elif 'm' in bitrate_str:
            bitrate_kbps = int(bitrate_str.replace('m', '')) * 1000
        else:
            bitrate_kbps = int(bitrate_str)
        
        # Calculate
        total_kilobits = bitrate_kbps * duration_seconds
        total_megabytes = total_kilobits / 8 / 1024
        
        return round(total_megabytes, 2)
