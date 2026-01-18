###################################################
# Potential Other Usage:
# PORT = 443 #IIS Web Server
# PORT = 445 #SMB Server
#####################################################

import multiprocessing
import logging
import pyradamsa #Only available on Linux
import random
import socket
import sys
import time
import hashlib
import json
import os
from collections import defaultdict
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, Tuple, Set
from enum import Enum


class FuzzingStrategy(Enum):
    """Different mutation strategies for better coverage"""
    RADAMSA = "radamsa"
    BIT_FLIP = "bit_flip"
    BYTE_FLIP = "byte_flip"
    BOUNDARY = "boundary"
    ARITHMETIC = "arithmetic"
    INTERESTING = "interesting"


@dataclass
class CrashSignature:
    """Represents a unique crash"""
    hash_sig: str
    rand_seed: int
    strategy: str
    timestamp: str
    exception_type: str
    payload_size: int
    mutation_count: int


class CrashDatabase:
    """Manages unique crashes and deduplicates similar ones"""
    def __init__(self, db_file: str = "crashes.json"):
        self.db_file = db_file
        self.crashes: dict = {}
        self.load()

    def add_crash(self, signature: CrashSignature) -> bool:
        """Returns True if crash is unique"""
        if signature.hash_sig in self.crashes:
            return False
        self.crashes[signature.hash_sig] = asdict(signature)
        self.save()
        return True

    def save(self):
        """Persist crashes to disk"""
        try:
            with open(self.db_file, 'w') as f:
                json.dump(self.crashes, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save crash database: {e}")

    def load(self):
        """Load crashes from disk"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    self.crashes = json.load(f)
            except Exception as e:
                logging.error(f"Failed to load crash database: {e}")

    def get_unique_count(self) -> int:
        """Return count of unique crashes"""
        return len(self.crashes)


class AdvancedFuzzer:
    """Enhanced fuzzer with multiple strategies and tracking"""
    
    def __init__(self, host: str, port: int, seed_file: str, timeout: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.rad = pyradamsa.Radamsa()
        
        # Load seed
        with open(seed_file, "rb") as fd:
            self.seed = fd.read()
        
        # Attempt to load secondary seed
        self.seed_v2 = None
        try:
            with open("moneyV2.dat", "rb") as fd:
                self.seed_v2 = fd.read()
        except FileNotFoundError:
            logging.warning("Secondary seed file 'moneyV2.dat' not found")
        
        # Setup logging
        self.setup_logging()
        
        # Initialize crash database
        self.crash_db = CrashDatabase()
        
        # Metrics
        self.mutation_count = 0
        self.crash_count = 0
        self.unique_crash_count = 0
        self.start_time = time.time()
        self.strategy_stats = defaultdict(int)
        
        logging.info(f"[*] Fuzzer initialized: {self.host}:{self.port}")
        logging.info(f"[*] Primary seed size: {len(self.seed)} bytes")
        if self.seed_v2:
            logging.info(f"[*] Secondary seed size: {len(self.seed_v2)} bytes")

    def setup_logging(self):
        """Configure logging"""
        log_file = f"fuzzer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # File handler
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)
        
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        logger.addHandler(fh)
        logger.addHandler(ch)

    def bit_flip(self, data: bytes, num_flips: int = 1) -> bytes:
        """Flip random bits in data"""
        data_array = bytearray(data)
        for _ in range(num_flips):
            byte_idx = random.randint(0, len(data_array) - 1)
            bit_idx = random.randint(0, 7)
            data_array[byte_idx] ^= (1 << bit_idx)
        return bytes(data_array)

    def byte_flip(self, data: bytes, num_flips: int = 1) -> bytes:
        """Flip random bytes in data"""
        data_array = bytearray(data)
        for _ in range(num_flips):
            byte_idx = random.randint(0, len(data_array) - 1)
            data_array[byte_idx] = random.randint(0, 255)
        return bytes(data_array)

    def boundary_mutation(self, data: bytes) -> bytes:
        """Insert boundary/interesting values"""
        interesting_values = [0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE]
        data_array = bytearray(data)
        idx = random.randint(0, len(data_array) - 1)
        data_array[idx] = random.choice(interesting_values)
        return bytes(data_array)

    def arithmetic_mutation(self, data: bytes) -> bytes:
        """Add/subtract from random bytes"""
        data_array = bytearray(data)
        idx = random.randint(0, len(data_array) - 1)
        delta = random.randint(-10, 10)
        data_array[idx] = (data_array[idx] + delta) % 256
        return bytes(data_array)

    def interesting_mutation(self, data: bytes) -> bytes:
        """Replace sequences with interesting patterns"""
        patterns = [
            b'\x00\x00\x00\x00',
            b'\xFF\xFF\xFF\xFF',
            b'\x7F\xFF\xFF\xFF',
            b'\x80\x00\x00\x00',
            b'A' * random.randint(10, 100),
        ]
        data_array = bytearray(data)
        pattern = random.choice(patterns)
        max_idx = max(0, len(data_array) - len(pattern))
        if max_idx > 0:
            idx = random.randint(0, max_idx)
            data_array[idx:idx+len(pattern)] = pattern
        return bytes(data_array)

    def generate_mutation(self, strategy: FuzzingStrategy, seed: bytes) -> Tuple[bytes, int]:
        """Generate mutated payload based on strategy"""
        rand_seed = random.randint(0, 0xFFFFFFFF)
        
        if strategy == FuzzingStrategy.RADAMSA:
            payload = self.rad.fuzz(seed, rand_seed)
        elif strategy == FuzzingStrategy.BIT_FLIP:
            payload = self.bit_flip(seed, num_flips=random.randint(1, 5))
        elif strategy == FuzzingStrategy.BYTE_FLIP:
            payload = self.byte_flip(seed, num_flips=random.randint(1, 3))
        elif strategy == FuzzingStrategy.BOUNDARY:
            payload = self.boundary_mutation(seed)
        elif strategy == FuzzingStrategy.ARITHMETIC:
            payload = self.arithmetic_mutation(seed)
        elif strategy == FuzzingStrategy.INTERESTING:
            payload = self.interesting_mutation(seed)
        else:
            payload = seed
        
        self.strategy_stats[strategy.value] += 1
        return payload, rand_seed

    def save_poc(self, payload: bytes, rand_seed: int, strategy: str):
        """Save proof-of-concept crash"""
        poc_file = f"poc_{strategy}_{rand_seed}_{int(time.time())}.poc"
        try:
            with open(poc_file, "wb") as fd:
                fd.write(payload)
            logging.info(f"[+] PoC saved to {poc_file}")
            return poc_file
        except Exception as e:
            logging.error(f"Failed to save PoC: {e}")
            return None

    def create_crash_signature(
        self, 
        payload: bytes, 
        rand_seed: int, 
        strategy: str, 
        exception: Exception
    ) -> CrashSignature:
        """Create unique crash signature"""
        payload_hash = hashlib.sha256(payload).hexdigest()
        
        return CrashSignature(
            hash_sig=payload_hash,
            rand_seed=rand_seed,
            strategy=strategy,
            timestamp=datetime.now().isoformat(),
            exception_type=type(exception).__name__,
            payload_size=len(payload),
            mutation_count=self.mutation_count
        )

    def send_payload(self, payload: bytes) -> bool:
        """Send payload to target, return True if successful"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.host, self.port))
            s.send(payload)
            s.close()
            return True
        except socket.timeout:
            return False
        except ConnectionRefusedError:
            return False
        except Exception:
            return False

    def reproducer(self, seed: bytes, rand_seed: int, strategy: str):
        """Attempt to reproduce crash after target reboot"""
        logging.info(f"[*] Waiting for target to reboot (seed={rand_seed}, strategy={strategy})...")
        time.sleep(0x30)  # 48 seconds
        
        for attempt in range(0x40):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((self.host, self.port))
                
                payload = self.rad.fuzz(seed, rand_seed)
                s.send(payload)
                s.close()
                
                logging.info(f"[+] Reproducer attempt {attempt + 1}/64 successful")
                return True
                
            except Exception as e:
                if attempt == 0x3F:
                    logging.error(f"[-] Reproducer failed after 64 attempts")
                    poc_file = self.save_poc(payload, rand_seed, strategy)
                    return False

    def fuzz_worker(self, worker_id: int, num_mutations: int):
        """Worker process for parallel fuzzing"""
        logging.info(f"[*] Fuzzer worker {worker_id} started")
        local_mutations = 0
        
        while local_mutations < num_mutations:
            try:
                # Randomly select strategy
                strategy = random.choice(list(FuzzingStrategy))
                
                # Select seed (primary or secondary)
                seed = self.seed if random.random() > 0.3 else (self.seed_v2 or self.seed)
                
                # Generate mutation
                payload, rand_seed = self.generate_mutation(strategy, seed)
                self.mutation_count += 1
                local_mutations += 1
                
                # Send payload
                if not self.send_payload(payload):
                    # Assume crash on timeout
                    self.crash_count += 1
                    exception = Exception("Timeout/Connection refused")
                    
                    sig = self.create_crash_signature(payload, rand_seed, strategy.value, exception)
                    if self.crash_db.add_crash(sig):
                        self.unique_crash_count += 1
                        logging.warning(
                            f"[!] UNIQUE CRASH #{self.unique_crash_count} (Worker {worker_id})\n"
                            f"    Seed: {rand_seed}\n"
                            f"    Strategy: {strategy.value}\n"
                            f"    Payload size: {len(payload)}\n"
                            f"    Hash: {sig.hash_sig}"
                        )
                        self.save_poc(payload, rand_seed, strategy.value)
                        self.reproducer(seed, rand_seed, strategy.value)
                    
                # Log progress periodically
                if local_mutations % 1000 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.mutation_count / elapsed if elapsed > 0 else 0
                    logging.info(
                        f"[*] Worker {worker_id}: {local_mutations} mutations | "
                        f"Total: {self.mutation_count} | "
                        f"Crashes: {self.unique_crash_count} | "
                        f"Rate: {rate:.1f} mut/sec"
                    )
                    
            except KeyboardInterrupt:
                logging.info(f"[*] Worker {worker_id} interrupted")
                break
            except Exception as e:
                logging.error(f"[!] Worker {worker_id} error: {e}")
                continue

    def print_stats(self):
        """Print fuzzing statistics"""
        elapsed = time.time() - self.start_time
        rate = self.mutation_count / elapsed if elapsed > 0 else 0
        
        stats_msg = (
            f"\n{'='*60}\n"
            f"FUZZING STATISTICS\n"
            f"{'='*60}\n"
            f"Total Mutations: {self.mutation_count}\n"
            f"Unique Crashes: {self.unique_crash_count}\n"
            f"Total Crashes: {self.crash_count}\n"
            f"Elapsed Time: {elapsed:.2f}s\n"
            f"Mutation Rate: {rate:.1f} mutations/sec\n"
            f"\nStrategy Distribution:\n"
        )
        
        for strategy, count in sorted(self.strategy_stats.items(), key=lambda x: x[1], reverse=True):
            pct = (count / self.mutation_count * 100) if self.mutation_count > 0 else 0
            stats_msg += f"  {strategy}: {count} ({pct:.1f}%)\n"
        
        stats_msg += f"{'='*60}\n"
        logging.info(stats_msg)

    def run_parallel(self, num_workers: int = 4, mutations_per_worker: int = 10000):
        """Run fuzzer with multiple worker processes"""
        logging.info(f"[*] Starting fuzzer with {num_workers} workers")
        logging.info(f"[*] Target mutations per worker: {mutations_per_worker}")
        
        processes = []
        try:
            for worker_id in range(num_workers):
                p = multiprocessing.Process(
                    target=self.fuzz_worker,
                    args=(worker_id, mutations_per_worker)
                )
                p.start()
                processes.append(p)
            
            # Wait for all workers
            for p in processes:
                p.join()
                
        except KeyboardInterrupt:
            logging.info("[*] Interrupt received, stopping workers...")
            for p in processes:
                p.terminate()
            for p in processes:
                p.join()
        
        self.print_stats()


def main():
    try:
        if len(sys.argv) < 3:
            print(f"Usage: python3 {sys.argv[0]} [HOST] [SEED_FILE] [NUM_WORKERS=4]")
            sys.exit(1)
        
        host = sys.argv[1]
        seed_file = sys.argv[2]
        num_workers = int(sys.argv[3]) if len(sys.argv) > 3 else 4
        
        fuzzer = AdvancedFuzzer(host, 3389, seed_file)
        fuzzer.run_parallel(num_workers=num_workers, mutations_per_worker=10000)
        
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        print(f"[*] Usage: python3 {sys.argv[0]} [HOST] [SEED_FILE] [NUM_WORKERS=4]")
        sys.exit(1)


if __name__ == "__main__":
    main()