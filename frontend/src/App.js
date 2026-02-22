import { useState, useEffect, useCallback } from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import axios from "axios";
import { Toaster } from "@/components/ui/sonner";
import { toast } from "sonner";

// Components
import { Sidebar } from "@/components/Sidebar";
import { Header } from "@/components/Header";
import { ChatInterface } from "@/components/ChatInterface";
import { ToolsPanel } from "@/components/ToolsPanel";
import { FileExplorer } from "@/components/FileExplorer";
import { TerminalOutput } from "@/components/TerminalOutput";
import { DisclaimerModal } from "@/components/DisclaimerModal";
import { QuickActions } from "@/components/QuickActions";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

function Dashboard() {
  const [sessions, setSessions] = useState([]);
  const [currentSession, setCurrentSession] = useState(null);
  const [messages, setMessages] = useState([]);
  const [tools, setTools] = useState({});
  const [toolCategories, setToolCategories] = useState([]);
  const [terminalOutput, setTerminalOutput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [files, setFiles] = useState([]);
  const [currentPath, setCurrentPath] = useState("/");
  const [currentTarget, setCurrentTarget] = useState("");
  const [disclaimerAccepted, setDisclaimerAccepted] = useState(() => {
    return localStorage.getItem("nexus_disclaimer_accepted") === "true";
  });

  const handleDisclaimerAccept = () => {
    localStorage.setItem("nexus_disclaimer_accepted", "true");
    setDisclaimerAccepted(true);
  };

  // Fetch sessions
  const fetchSessions = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/sessions`);
      setSessions(response.data.sessions || []);
    } catch (e) {
      console.error("Error fetching sessions:", e);
    }
  }, []);

  // Fetch tools
  const fetchTools = useCallback(async () => {
    try {
      const response = await axios.get(`${API}/tools`);
      setTools(response.data.tools || {});
      setToolCategories(response.data.categories || []);
    } catch (e) {
      console.error("Error fetching tools:", e);
    }
  }, []);

  // Fetch chat history
  const fetchChatHistory = useCallback(async (sessionId) => {
    try {
      const response = await axios.get(`${API}/chat/history/${sessionId}`);
      setMessages(response.data.messages || []);
    } catch (e) {
      console.error("Error fetching chat history:", e);
    }
  }, []);

  // Fetch files
  const fetchFiles = useCallback(async (path = "/") => {
    try {
      const response = await axios.get(`${API}/files/list?path=${encodeURIComponent(path)}`);
      if (response.data.status === "success" && response.data.items) {
        setFiles(response.data.items);
      } else {
        setFiles([]);
      }
      setCurrentPath(path);
    } catch (e) {
      console.error("Error fetching files:", e);
      setFiles([]);
    }
  }, []);

  // Initialize sandbox
  const initSandbox = useCallback(async () => {
    try {
      await axios.post(`${API}/files/init-sandbox`);
      fetchFiles("/");
    } catch (e) {
      console.error("Error initializing sandbox:", e);
    }
  }, [fetchFiles]);

  // Create new session
  const createSession = async (name = "New Session") => {
    try {
      const response = await axios.post(`${API}/sessions?name=${encodeURIComponent(name)}`);
      const newSession = response.data;
      setSessions(prev => [newSession, ...prev]);
      setCurrentSession(newSession);
      setMessages([]);
      toast.success("New session created");
    } catch (e) {
      toast.error("Failed to create session");
    }
  };

  // Delete session
  const deleteSession = async (sessionId) => {
    try {
      await axios.delete(`${API}/sessions/${sessionId}`);
      setSessions(prev => prev.filter(s => s.id !== sessionId));
      if (currentSession?.id === sessionId) {
        setCurrentSession(null);
        setMessages([]);
      }
      toast.success("Session deleted");
    } catch (e) {
      toast.error("Failed to delete session");
    }
  };

  // Send message
  const sendMessage = async (message) => {
    let sessionId = currentSession?.id;
    
    // Create session if none exists
    if (!sessionId) {
      try {
        const response = await axios.post(`${API}/sessions?name=${encodeURIComponent("New Session")}`);
        const newSession = response.data;
        setSessions(prev => [newSession, ...prev]);
        setCurrentSession(newSession);
        sessionId = newSession.id;
        toast.success("New session created");
      } catch (e) {
        toast.error("Failed to create session");
        return;
      }
    }

    setIsLoading(true);
    
    // Add user message immediately
    const userMsg = {
      id: Date.now().toString(),
      role: "user",
      content: message,
      timestamp: new Date().toISOString()
    };
    setMessages(prev => [...prev, userMsg]);

    try {
      const response = await axios.post(`${API}/chat`, {
        session_id: sessionId,
        message: message
      });

      // Add assistant response
      const assistantMsg = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: response.data.response,
        tool_calls: response.data.tool_calls,
        timestamp: new Date().toISOString()
      };
      setMessages(prev => [...prev, assistantMsg]);
    } catch (e) {
      toast.error("Failed to send message");
      console.error("Chat error:", e);
    } finally {
      setIsLoading(false);
    }
  };

  // Execute tool
  const executeTool = async (toolName, params = {}) => {
    if (!currentSession) {
      toast.error("No active session");
      return;
    }

    setTerminalOutput(prev => prev + `\n[*] Executing ${toolName}...\n`);

    try {
      const response = await axios.post(`${API}/tools/execute`, {
        tool_name: toolName,
        parameters: params,
        session_id: currentSession.id
      });

      const output = `\n[+] ${toolName.toUpperCase()} Results:\n${response.data.output}\n[*] Execution time: ${response.data.execution_time.toFixed(2)}s\n`;
      setTerminalOutput(prev => prev + output);
      toast.success(`${toolName} executed successfully`);
    } catch (e) {
      setTerminalOutput(prev => prev + `\n[-] Error executing ${toolName}\n`);
      toast.error(`Failed to execute ${toolName}`);
    }
  };

  // Execute workflow
  const executeWorkflow = async (workflowId, target) => {
    // Auto-create session if needed
    let sessionId = currentSession?.id;
    if (!sessionId) {
      try {
        const response = await axios.post(`${API}/sessions?name=${encodeURIComponent(`Scan: ${target}`)}`);
        const newSession = response.data;
        setSessions(prev => [newSession, ...prev]);
        setCurrentSession(newSession);
        sessionId = newSession.id;
      } catch (e) {
        toast.error("Failed to create session");
        return;
      }
    }

    setTerminalOutput(prev => prev + `\n${"=".repeat(60)}\n[*] STARTING WORKFLOW: ${workflowId.toUpperCase()}\n[*] TARGET: ${target}\n${"=".repeat(60)}\n`);
    
    try {
      const response = await axios.post(`${API}/workflows/execute`, {
        workflow_id: workflowId,
        target: target,
        session_id: sessionId
      });

      // Display results
      for (const result of response.data.results) {
        setTerminalOutput(prev => prev + `\n[+] ${result.tool.toUpperCase()}:\n${result.output}\n`);
      }
      
      setTerminalOutput(prev => prev + `\n${"=".repeat(60)}\n[+] WORKFLOW COMPLETE: ${response.data.tools_executed} tools executed\n${"=".repeat(60)}\n`);
      toast.success(`Workflow complete: ${response.data.tools_executed} tools executed`);
    } catch (e) {
      setTerminalOutput(prev => prev + `\n[-] Workflow execution failed\n`);
      toast.error("Workflow execution failed");
    }
  };

  // File operations
  const readFile = async (path) => {
    try {
      const response = await axios.post(`${API}/files/operation`, {
        operation: "read",
        path: path
      });
      if (response.data.status === "success") {
        setTerminalOutput(prev => prev + `\n[*] Reading ${path}:\n${response.data.output}\n`);
      } else {
        toast.error(response.data.output);
      }
    } catch (e) {
      toast.error("Failed to read file");
    }
  };

  // Initial data load
  useEffect(() => {
    fetchSessions();
    fetchTools();
    initSandbox();
  }, [fetchSessions, fetchTools, initSandbox]);

  // Load chat history when session changes
  useEffect(() => {
    if (currentSession?.id) {
      fetchChatHistory(currentSession.id);
    }
  }, [currentSession, fetchChatHistory]);

  // Select session
  const selectSession = (session) => {
    setCurrentSession(session);
    setSidebarOpen(false);
  };

  // Show disclaimer if not accepted
  if (!disclaimerAccepted) {
    return (
      <>
        <DisclaimerModal onAccept={handleDisclaimerAccept} />
        <Toaster position="bottom-right" theme="dark" />
      </>
    );
  }

  return (
    <div className="app-container" data-testid="app-container">
      {/* Mobile Overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <Sidebar
        sessions={sessions}
        currentSession={currentSession}
        onSelectSession={selectSession}
        onCreateSession={createSession}
        onDeleteSession={deleteSession}
        isOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />

      {/* Main Content */}
      <div className="main-content">
        <Header 
          onMenuClick={() => setSidebarOpen(!sidebarOpen)}
          currentSession={currentSession}
        />

        <div className="bento-grid">
          {/* Chat Panel */}
          <div className="chat-panel" data-testid="chat-panel">
            <ChatInterface
              messages={messages}
              onSendMessage={sendMessage}
              isLoading={isLoading}
            />
          </div>

          {/* Tools Panel */}
          <div className="tools-panel" data-testid="tools-panel">
            <ToolsPanel
              tools={tools}
              categories={toolCategories}
              onExecuteTool={executeTool}
            />
          </div>

          {/* Terminal Output */}
          <div className="chat-panel" style={{ gridColumn: 'span 8' }} data-testid="terminal-panel">
            <TerminalOutput output={terminalOutput} onClear={() => setTerminalOutput("")} />
          </div>

          {/* File Explorer */}
          <div className="file-explorer" data-testid="file-explorer">
            <FileExplorer
              files={files}
              currentPath={currentPath}
              onNavigate={fetchFiles}
              onReadFile={readFile}
            />
          </div>
        </div>
      </div>

      <Toaster position="bottom-right" theme="dark" />
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
