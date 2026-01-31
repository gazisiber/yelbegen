import multiprocessing as mp
from multiprocessing import Queue, Process
from typing import List, Dict, Any, Callable
import time
import traceback


def _worker_wrapper(module_name: str, module_func: Callable, target: str, result_queue: Queue, api_key: str = None):
    """
    Worker wrapper that handles both free and API-based modules
    """
    try:
        result_queue.put({
            'type': 'status',
            'module': module_name,
            'status': 'started',
            'timestamp': time.time()
        })
        
        # Call module function with or without API key
        if api_key is not None:
            result = module_func(target, api_key)
        else:
            result = module_func(target)
        
        result_queue.put({
            'type': 'result',
            'module': module_name,
            'status': 'completed',
            'data': result,
            'timestamp': time.time()
        })
        
    except Exception as e:
        result_queue.put({
            'type': 'error',
            'module': module_name,
            'status': 'failed',
            'error': str(e),
            'traceback': traceback.format_exc(),
            'timestamp': time.time()
        })
    finally:
        # Always send done signal, even if error occurred
        # This ensures main loop knows this worker has finished
        result_queue.put({
            'type': 'worker_done',
            'module': module_name,
            'timestamp': time.time()
        })


class ReconEngine:
    
    def __init__(self):
        self.result_queue = None
        self.processes = []
        self.is_running = False
        
    
    def start_scan(self, target: str, modules: List[Dict[str, Any]], mode: str = 'basic') -> Queue:
        """
        Start scanning with mode support
        mode: 'basic' (free modules only) or 'full' (includes API modules if keys available)
        """
        self.result_queue = mp.Queue()
        self.processes = []
        self.is_running = True
        
        self.result_queue.put({
            'type': 'status',
            'module': 'engine',
            'status': 'scan_started',
            'target': target,
            'mode': mode,
            'module_count': len(modules),
            'timestamp': time.time()
        })
        
        for module in modules:
            module_name = module['name']
            module_func = module['function']
            
            # Prepare args for worker - add API key if module requires it
            if module.get('requires_key') and module.get('api_key'):
                # Module requires key and we have one
                worker_args = (module_name, module_func, target, self.result_queue, module['api_key'])
            else:
                # Free module or no key provided
                worker_args = (module_name, module_func, target, self.result_queue, None)
            
            process = Process(
                target=_worker_wrapper,
                args=worker_args,
                daemon=True
            )
            process.start()
            self.processes.append({
                'name': module_name,
                'process': process
            })
        
        return self.result_queue
    
    def stop_scan(self):
        self.is_running = False
        
        for proc_info in self.processes:
            process = proc_info['process']
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
                if process.is_alive():
                    process.kill()
        
        self.processes.clear()
        
        if self.result_queue:
            self.result_queue.put({
                'type': 'status',
                'module': 'engine',
                'status': 'scan_stopped',
                'timestamp': time.time()
            })
    
    def is_scan_complete(self) -> bool:
        if not self.processes:
            return True
        
        return all(not proc_info['process'].is_alive() for proc_info in self.processes)
    
    def cleanup(self):
        self.stop_scan()
        if self.result_queue:
            while not self.result_queue.empty():
                try:
                    self.result_queue.get_nowait()
                except:
                    break
