import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Network, 
  Globe, 
  Key, 
  Bug, 
  Wifi, 
  Search,
  Play,
  ChevronDown,
  ChevronRight,
  Pause,
  SkipForward,
  Zap,
  FileSearch,
  Users,
  X
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";

const categoryIcons = {
  network: Network,
  web: Globe,
  password: Key,
  exploitation: Bug,
  wireless: Wifi,
  recon: Search,
  forensics: FileSearch,
  social: Users,
  exfiltration: Zap,
  postexploit: Bug,
  pivoting: Network,
};

const categoryColors = {
  network: "#00FF41",
  web: "#00F0FF",
  password: "#FFB000",
  exploitation: "#FF3B30",
  wireless: "#9B59B6",
  recon: "#3498DB",
  forensics: "#E91E63",
  social: "#FF9800",
  exfiltration: "#00BCD4",
  postexploit: "#8BC34A",
  pivoting: "#607D8B",
};

// Smart defaults based on tool type
const getSmartDefaults = (toolId) => {
  const defaults = {
    // Network
    nmap: { target: "192.168.1.0/24", port: "1-1000", options: "-sV -sC" },
    netcat: { target: "192.168.1.1", port: "80", options: "-v" },
    masscan: { target: "192.168.1.0/24", port: "1-65535", rate: "10000" },
    responder: { interface: "eth0", options: "-wrf" },
    ettercap: { target: "192.168.1.0/24", interface: "eth0" },
    
    // Web
    nikto: { target: "192.168.1.1", port: "80", options: "-Tuning 123bde" },
    sqlmap: { target: "http://target.com/page?id=1", level: "3", risk: "2" },
    dirb: { target: "http://192.168.1.1", wordlist: "common.txt" },
    gobuster: { target: "http://192.168.1.1", wordlist: "common.txt", threads: "50" },
    wpscan: { target: "http://192.168.1.1", enumerate: "vp,vt,u" },
    ffuf: { target: "http://192.168.1.1/FUZZ", wordlist: "common.txt" },
    xsstrike: { target: "http://target.com/search?q=test" },
    
    // Password
    hydra: { target: "192.168.1.1", service: "ssh", port: "22", wordlist: "rockyou.txt" },
    john: { hash: "hash.txt", wordlist: "rockyou.txt", format: "auto" },
    hashcat: { hash: "hashes.txt", mode: "0", wordlist: "rockyou.txt" },
    mimikatz: { target: "local", command: "sekurlsa::logonpasswords" },
    
    // Exploitation
    metasploit: { target: "192.168.1.1", lhost: "192.168.1.100", lport: "4444" },
    searchsploit: { query: "apache 2.4", options: "-w" },
    msfvenom: { payload: "windows/meterpreter/reverse_tcp", lhost: "192.168.1.100", lport: "4444" },
    
    // Recon
    whois: { target: "example.com" },
    theHarvester: { target: "example.com", sources: "google,bing,linkedin" },
    subfinder: { target: "example.com", sources: "all" },
    dnsrecon: { target: "example.com", type: "std" },
    amass: { target: "example.com", mode: "enum" },
    
    // Forensics
    binwalk: { file: "firmware.bin", extract: "true" },
    exiftool: { file: "image.jpg", all: "true" },
    volatility: { memory: "memory.dmp", profile: "Win10x64" },
    
    // Post-Exploitation
    bloodhound: { target: "dc01.corp.local", domain: "corp.local" },
    crackmapexec: { target: "192.168.1.0/24", user: "administrator", password: "P@ssw0rd" },
    linpeas: { target: "local", output: "/tmp/linpeas.txt" },
    winpeas: { target: "local", output: "C:\\temp\\winpeas.txt" },
    lazagne: { target: "all", output: "credentials.txt" },
    rubeus: { command: "kerberoast", domain: "corp.local" },
    impacket: { target: "192.168.1.10", domain: "corp.local", user: "administrator" },
    
    // Exfiltration
    dnscat2: { server: "192.168.1.100", domain: "exfil.com" },
    chisel: { target: "192.168.1.100", port: "8080", mode: "server" },
    cloakify: { file: "data.zip", cipher: "pokemon" },
    
    // Pivoting
    sshuttle: { target: "192.168.1.50", subnet: "10.10.10.0/24" },
    ligolo: { target: "192.168.1.50", port: "11601" },
    proxychains: { config: "/etc/proxychains.conf" },
  };
  return defaults[toolId] || { target: "192.168.1.1" };
};

export const ToolsPanel = ({ tools, categories, onExecuteTool, currentTarget }) => {
  const [expandedCategory, setExpandedCategory] = useState("network");
  const [selectedTool, setSelectedTool] = useState(null);
  const [toolParams, setToolParams] = useState({});
  const [dialogOpen, setDialogOpen] = useState(false);
  const [countdown, setCountdown] = useState(5);
  const [isPaused, setIsPaused] = useState(false);
  const [autoExecute, setAutoExecute] = useState(true);
  const countdownRef = useRef(null);

  // Auto-countdown effect
  useEffect(() => {
    if (dialogOpen && autoExecute && !isPaused && countdown > 0) {
      countdownRef.current = setTimeout(() => {
        setCountdown(prev => prev - 1);
      }, 1000);
    } else if (dialogOpen && countdown === 0 && autoExecute) {
      handleExecute();
    }

    return () => {
      if (countdownRef.current) {
        clearTimeout(countdownRef.current);
      }
    };
  }, [dialogOpen, countdown, isPaused, autoExecute]);

  const handleToolClick = (tool) => {
    const defaults = getSmartDefaults(tool.id);
    // Use current target if available
    if (currentTarget) {
      defaults.target = currentTarget;
    }
    setSelectedTool(tool);
    setToolParams(defaults);
    setCountdown(5);
    setIsPaused(false);
    setDialogOpen(true);
  };

  const handleExecute = () => {
    if (selectedTool) {
      onExecuteTool(selectedTool.id, toolParams);
      setDialogOpen(false);
      setCountdown(5);
    }
  };

  const handlePauseResume = () => {
    setIsPaused(!isPaused);
  };

  const handleSkip = () => {
    setCountdown(0);
  };

  const handleCancel = () => {
    setDialogOpen(false);
    setCountdown(5);
    setIsPaused(false);
  };

  const toggleCategory = (category) => {
    setExpandedCategory(expandedCategory === category ? null : category);
  };

  return (
    <div className="flex flex-col h-full" data-testid="tools-panel-container">
      {/* Header */}
      <div className="panel-header">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-[#00FF41]" />
          <span className="panel-title">KALI TOOLS</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-[#00FF41]">AUTO</span>
          <span className="text-[10px] font-mono text-[#666666]">
            {Object.values(tools).flat().length} AVAILABLE
          </span>
        </div>
      </div>

      {/* Tools List */}
      <ScrollArea className="flex-1">
        <div className="p-3 space-y-2">
          {categories.map((category) => {
            const Icon = categoryIcons[category] || Network;
            const color = categoryColors[category] || "#00FF41";
            const categoryTools = tools[category] || [];
            const isExpanded = expandedCategory === category;

            return (
              <div key={category} className="border border-white/5">
                {/* Category Header */}
                <button
                  onClick={() => toggleCategory(category)}
                  className="w-full flex items-center justify-between p-3 hover:bg-white/5 transition-colors"
                  data-testid={`category-${category}`}
                >
                  <div className="flex items-center gap-3">
                    <div 
                      className="w-8 h-8 flex items-center justify-center"
                      style={{ backgroundColor: `${color}15`, border: `1px solid ${color}40` }}
                    >
                      <Icon className="w-4 h-4" style={{ color }} />
                    </div>
                    <div className="text-left">
                      <span className="font-mono text-xs text-white/90 uppercase tracking-wider">
                        {category}
                      </span>
                      <span className="block text-[10px] text-[#666666]">
                        {categoryTools.length} tools
                      </span>
                    </div>
                  </div>
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-[#666666]" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-[#666666]" />
                  )}
                </button>

                {/* Tools Grid */}
                <AnimatePresence>
                  {isExpanded && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.2 }}
                      className="overflow-hidden"
                    >
                      <div className="tool-grid border-t border-white/5">
                        {categoryTools.map((tool) => (
                          <motion.div
                            key={tool.id}
                            whileHover={{ scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                            onClick={(e) => {
                              e.stopPropagation();
                              handleToolClick(tool);
                            }}
                            className="tool-card p-3 bg-black/30 border border-white/5 text-left cursor-pointer"
                            data-testid={`tool-${tool.id}`}
                          >
                            <div className="flex items-center justify-between mb-2">
                              <span 
                                className="font-mono text-xs font-semibold"
                                style={{ color }}
                              >
                                {tool.name}
                              </span>
                              <div 
                                className="w-2 h-2 rounded-full"
                                style={{ backgroundColor: color }}
                              />
                            </div>
                            <p className="text-[10px] text-[#666666] line-clamp-2">
                              {tool.description}
                            </p>
                          </motion.div>
                        ))}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      </ScrollArea>

      {/* Auto-Execute Tool Dialog */}
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="bg-[#0A0A0A] border border-[rgba(0,255,65,0.3)] max-w-lg">
          <DialogHeader>
            <DialogTitle className="font-mono text-[#00FF41] tracking-wider flex items-center gap-2">
              <Zap className="w-5 h-5" />
              {selectedTool?.name?.toUpperCase()}
            </DialogTitle>
            <DialogDescription className="text-[#666666]">
              {selectedTool?.description}
            </DialogDescription>
          </DialogHeader>

          {/* Auto-execute countdown */}
          <div className="bg-black/50 border border-[#00FF41]/20 p-4 mb-4">
            <div className="flex items-center justify-between mb-2">
              <span className="font-mono text-xs text-[#00FF41]">
                {isPaused ? "PAUSED" : `AUTO-EXECUTING IN ${countdown}s`}
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={handlePauseResume}
                  className="p-1.5 text-[#FFB000] hover:bg-[#FFB000]/10 transition-colors"
                  title={isPaused ? "Resume" : "Pause"}
                >
                  {isPaused ? <Play className="w-4 h-4" /> : <Pause className="w-4 h-4" />}
                </button>
                <button
                  onClick={handleSkip}
                  className="p-1.5 text-[#00FF41] hover:bg-[#00FF41]/10 transition-colors"
                  title="Execute Now"
                >
                  <SkipForward className="w-4 h-4" />
                </button>
                <button
                  onClick={handleCancel}
                  className="p-1.5 text-[#FF3B30] hover:bg-[#FF3B30]/10 transition-colors"
                  title="Cancel"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
            <Progress 
              value={((5 - countdown) / 5) * 100} 
              className="h-1 bg-black"
            />
          </div>

          {/* Parameters - editable during countdown */}
          <div className="space-y-3">
            {Object.entries(toolParams).map(([key, value]) => (
              <div key={key} className="space-y-1">
                <Label className="font-mono text-[10px] text-white/50 uppercase tracking-wider">
                  {key}
                </Label>
                <Input
                  value={value}
                  onChange={(e) => {
                    setToolParams({ ...toolParams, [key]: e.target.value });
                    setIsPaused(true); // Pause on edit
                  }}
                  className="bg-black border-[rgba(0,255,65,0.2)] text-[#00FF41] font-mono text-sm focus:border-[#00FF41] h-8"
                  data-testid={`tool-param-${key}`}
                />
              </div>
            ))}
          </div>

          {/* Quick actions */}
          <div className="flex gap-2 mt-4">
            <Button
              onClick={handleCancel}
              variant="outline"
              className="flex-1 border-white/10 text-white/70 hover:bg-white/5 font-mono text-xs"
            >
              CANCEL
            </Button>
            <Button
              onClick={handleExecute}
              className="flex-1 bg-[#00FF41]/10 border border-[#00FF41]/30 text-[#00FF41] hover:bg-[#00FF41]/20 font-mono text-xs"
              data-testid="tool-execute-btn"
            >
              <Play className="w-4 h-4 mr-2" />
              EXECUTE NOW
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
};
