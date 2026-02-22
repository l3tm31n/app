#!/usr/bin/env python3
"""
Backend API Testing for NEXUS Pentest LLM
Tests all core endpoints: sessions, chat, tools, file operations
"""

import requests
import json
import sys
from datetime import datetime
import time

class PentestAPITester:
    def __init__(self, base_url="https://security-ai-sandbox.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.session_id = None
        self.tests_run = 0
        self.tests_passed = 0
        
    def log(self, message):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        
    def run_test(self, name, method, endpoint, expected_status, data=None, headers=None):
        """Execute a single API test"""
        url = f"{self.api_url}/{endpoint}"
        if headers is None:
            headers = {'Content-Type': 'application/json'}
            
        self.tests_run += 1
        self.log(f"Testing {name}...")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=30)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                self.log(f"✅ {name} - Status: {response.status_code}")
                try:
                    return success, response.json()
                except:
                    return success, response.text
            else:
                self.log(f"❌ {name} - Expected {expected_status}, got {response.status_code}")
                self.log(f"   Response: {response.text[:200]}")
                return False, {}
                
        except requests.exceptions.Timeout:
            self.log(f"❌ {name} - Request timed out")
            return False, {}
        except Exception as e:
            self.log(f"❌ {name} - Error: {str(e)}")
            return False, {}
    
    def test_api_root(self):
        """Test API root endpoint"""
        return self.run_test("API Root", "GET", "", 200)
    
    def test_tools_endpoint(self):
        """Test tools listing endpoint"""
        success, response = self.run_test("Tools List", "GET", "tools", 200)
        if success:
            tools = response.get('tools', {})
            categories = response.get('categories', [])
            if len(categories) >= 5 and len(tools) > 0:
                self.log(f"   Found {len(categories)} categories with tools")
                return True
            else:
                self.log(f"   Warning: Limited tools found - {len(categories)} categories")
        return success
    
    def test_create_session(self):
        """Test session creation"""
        success, response = self.run_test(
            "Create Session", 
            "POST", 
            "sessions?name=Test%20Session", 
            200
        )
        if success and 'id' in response:
            self.session_id = response['id']
            self.log(f"   Session created: {self.session_id}")
        return success
    
    def test_get_sessions(self):
        """Test getting sessions list"""
        success, response = self.run_test("Get Sessions", "GET", "sessions", 200)
        if success:
            sessions = response.get('sessions', [])
            self.log(f"   Found {len(sessions)} sessions")
        return success
    
    def test_chat_functionality(self):
        """Test chat endpoint with AI response"""
        if not self.session_id:
            self.log("❌ Chat test - No session ID available")
            return False
            
        chat_data = {
            "session_id": self.session_id,
            "message": "scan network with nmap"
        }
        
        success, response = self.run_test("Chat AI Response", "POST", "chat", 200, chat_data)
        if success:
            if 'response' in response and len(response['response']) > 10:
                self.log(f"   AI responded with {len(response['response'])} characters")
                return True
            else:
                self.log("   Warning: AI response seems too short")
        return success
    
    def test_chat_history(self):
        """Test chat history retrieval"""
        if not self.session_id:
            return False
            
        success, response = self.run_test(
            "Chat History", 
            "GET", 
            f"chat/history/{self.session_id}", 
            200
        )
        if success:
            messages = response.get('messages', [])
            self.log(f"   Found {len(messages)} messages in history")
        return success
    
    def test_tool_execution(self):
        """Test tool execution (simulated)"""
        if not self.session_id:
            return False
            
        tool_data = {
            "tool_name": "nmap",
            "parameters": {"target": "192.168.1.1", "port": "80"},
            "session_id": self.session_id
        }
        
        success, response = self.run_test("Tool Execution", "POST", "tools/execute", 200, tool_data)
        if success:
            if 'output' in response and 'execution_time' in response:
                self.log(f"   Tool executed in {response.get('execution_time', 0):.2f}s")
                return True
        return success
    
    def test_file_operations(self):
        """Test file system operations"""
        # Test sandbox initialization
        success1, _ = self.run_test("Init Sandbox", "POST", "files/init-sandbox", 200)
        
        # Test file listing
        success2, response = self.run_test("List Files", "GET", "files/list", 200)
        if success2 and 'items' in response:
            items = response.get('items', [])
            self.log(f"   Found {len(items)} files/directories")
        
        # Test file write operation
        file_data = {
            "operation": "write",
            "path": "test_report.txt",
            "content": "Test file content from API test"
        }
        success3, _ = self.run_test("Write File", "POST", "files/operation", 200, file_data)
        
        return success1 and success2 and success3
    
    def test_session_cleanup(self):
        """Test session deletion"""
        if not self.session_id:
            return True  # No session to clean up
            
        success, _ = self.run_test(
            "Delete Session", 
            "DELETE", 
            f"sessions/{self.session_id}", 
            200
        )
        return success
    
    def run_all_tests(self):
        """Execute complete backend test suite"""
        self.log("=" * 60)
        self.log("NEXUS PENTEST LLM - BACKEND API TESTING")
        self.log("=" * 60)
        
        # Test sequence
        tests = [
            ("API Root", self.test_api_root),
            ("Tools Endpoint", self.test_tools_endpoint), 
            ("Create Session", self.test_create_session),
            ("Get Sessions", self.test_get_sessions),
            ("Chat Functionality", self.test_chat_functionality),
            ("Chat History", self.test_chat_history),
            ("Tool Execution", self.test_tool_execution),
            ("File Operations", self.test_file_operations),
            ("Session Cleanup", self.test_session_cleanup),
        ]
        
        for test_name, test_func in tests:
            try:
                test_func()
                time.sleep(0.5)  # Brief pause between tests
            except Exception as e:
                self.log(f"❌ {test_name} - Exception: {str(e)}")
        
        # Results summary
        self.log("=" * 60)
        success_rate = (self.tests_passed / self.tests_run * 100) if self.tests_run > 0 else 0
        self.log(f"BACKEND TESTING COMPLETE")
        self.log(f"Tests Passed: {self.tests_passed}/{self.tests_run} ({success_rate:.1f}%)")
        
        if success_rate >= 80:
            self.log("✅ Backend API is functioning well")
            return True
        elif success_rate >= 60:
            self.log("⚠️  Backend has some issues but is mostly functional")
            return True
        else:
            self.log("❌ Backend has significant issues")
            return False

def main():
    tester = PentestAPITester()
    success = tester.run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())