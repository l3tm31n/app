import { useState } from "react";
import { motion } from "framer-motion";
import { 
  Zap, 
  Play, 
  Target,
  Globe,
  Network,
  Key,
  Search,
  Clock
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const WORKFLOWS = {
  quick_recon: {
    name: "Quick Recon",
    icon: Search,
    color: "#3498DB",
    description: "Fast initial assessment",
    tools: ["whois", "nmap", "theHarvester"]
  },
  web_app_audit: {
    name: "Web App Audit",
    icon: Globe,
    color: "#00F0FF",
    description: "Web security scan",
    tools: ["nmap", "nikto", "dirb", "sqlmap"]
  },
  network_sweep: {
    name: "Network Sweep",
    icon: Network,
    color: "#00FF41",
    description: "Full network enum",
    tools: ["nmap", "masscan", "arp-scan"]
  },
  credential_audit: {
    name: "Credential Audit",
    icon: Key,
    color: "#FFB000",
    description: "Password testing",
    tools: ["hydra", "john", "hashcat"]
  },
  full_pentest: {
    name: "Full Pentest",
    icon: Zap,
    color: "#FF3B30",
    description: "Complete assessment",
    tools: ["All tools chained"]
  }
};

export const QuickActions = ({ onExecuteWorkflow, onSetTarget }) => {
  const [target, setTarget] = useState("");
  const [selectedWorkflow, setSelectedWorkflow] = useState("");
  const [isExecuting, setIsExecuting] = useState(false);

  const handleExecute = async () => {
    if (!target || !selectedWorkflow) return;
    
    setIsExecuting(true);
    onSetTarget(target);
    await onExecuteWorkflow(selectedWorkflow, target);
    setIsExecuting(false);
  };

  const handleQuickScan = (workflowId) => {
    if (!target) return;
    setSelectedWorkflow(workflowId);
    onSetTarget(target);
    onExecuteWorkflow(workflowId, target);
  };

  return (
    <div className="bg-[#0A0A0A] border border-[rgba(0,255,65,0.2)] p-4" data-testid="quick-actions">
      {/* Target Input */}
      <div className="flex gap-2 mb-4">
        <div className="relative flex-1">
          <Target className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#666666]" />
          <Input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Enter target (IP, domain, or range)"
            className="pl-10 bg-black border-[rgba(0,255,65,0.2)] text-[#00FF41] font-mono text-sm focus:border-[#00FF41]"
            data-testid="target-input"
          />
        </div>
        <Select value={selectedWorkflow} onValueChange={setSelectedWorkflow}>
          <SelectTrigger className="w-[180px] bg-black border-[rgba(0,255,65,0.2)] text-white font-mono text-xs">
            <SelectValue placeholder="Select workflow" />
          </SelectTrigger>
          <SelectContent className="bg-[#0A0A0A] border-[rgba(0,255,65,0.3)]">
            {Object.entries(WORKFLOWS).map(([id, workflow]) => (
              <SelectItem 
                key={id} 
                value={id}
                className="font-mono text-xs text-white hover:bg-[#00FF41]/10"
              >
                {workflow.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          onClick={handleExecute}
          disabled={!target || !selectedWorkflow || isExecuting}
          className="bg-[#00FF41]/10 border border-[#00FF41]/30 text-[#00FF41] hover:bg-[#00FF41]/20 font-mono text-xs px-6"
          data-testid="execute-workflow-btn"
        >
          {isExecuting ? (
            <Clock className="w-4 h-4 animate-spin" />
          ) : (
            <>
              <Play className="w-4 h-4 mr-2" />
              RUN
            </>
          )}
        </Button>
      </div>

      {/* Quick Workflow Buttons */}
      <div className="grid grid-cols-5 gap-2">
        {Object.entries(WORKFLOWS).map(([id, workflow]) => {
          const Icon = workflow.icon;
          return (
            <motion.button
              key={id}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={() => handleQuickScan(id)}
              disabled={!target}
              className="p-3 bg-black/50 border border-white/5 hover:border-white/20 disabled:opacity-30 disabled:cursor-not-allowed transition-colors group"
              data-testid={`workflow-${id}`}
            >
              <div 
                className="w-8 h-8 mx-auto mb-2 flex items-center justify-center rounded"
                style={{ backgroundColor: `${workflow.color}15`, border: `1px solid ${workflow.color}40` }}
              >
                <Icon className="w-4 h-4" style={{ color: workflow.color }} />
              </div>
              <span className="block font-mono text-[10px] text-white/70 group-hover:text-white truncate">
                {workflow.name}
              </span>
            </motion.button>
          );
        })}
      </div>
    </div>
  );
};
