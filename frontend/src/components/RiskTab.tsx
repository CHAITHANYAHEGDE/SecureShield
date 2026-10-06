import React from 'react';
import type { AnalysisResponse } from '../api';
import { ProvenanceBadge } from './ProvenanceBadge';
import { ShieldAlert, Crosshair, Search, RotateCcw, AlertTriangle } from 'lucide-react';

interface Props {
  analysis: AnalysisResponse;
}

export const RiskTab: React.FC<Props> = ({ analysis }) => {
  const isHighRisk = analysis.risk.score >= 70;

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      
      {/* Risk Summary Header */}
      <div className="flex flex-col md:flex-row gap-8 items-start border-b border-hairline pb-8">
        <div className="flex-shrink-0 flex flex-col items-center justify-center p-6 bg-surface border border-hairline rounded min-w-[200px]">
          <div className="mono-label text-gray-400 mb-4">THREAT SCORE</div>
          <div className={`text-6xl font-display font-bold tracking-tighter ${isHighRisk ? 'text-severity-critical' : 'text-severity-medium'}`}>
            {analysis.risk.score}
          </div>
          <div className="text-[10px] font-mono text-gray-500 mt-2 tracking-widest uppercase">{analysis.risk.severity} SEVERITY</div>
          <div className="mt-4"><ProvenanceBadge provenance={analysis.risk.provenance} /></div>
        </div>
        
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-3 text-gray-300">
            <AlertTriangle className="w-5 h-5 text-accent" />
            <h3 className="mono-label text-gray-300 m-0">Critical Threat Factors</h3>
          </div>
          <div className="bg-surface border border-hairline rounded p-5">
            {(!analysis.risk.factors || analysis.risk.factors.length === 0) ? (
              <div className="text-gray-500 font-mono italic">No specific threat factors articulated.</div>
            ) : (
              <ul className="space-y-3">
                {analysis.risk.factors.map((factor, i) => (
                  <li key={i} className="flex items-start text-sm text-gray-300 leading-relaxed">
                    <span className="text-accent font-bold mr-3 shrink-0">→</span>
                    {factor as unknown as string}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
      
      {/* Playbook */}
      <div>
        <div className="flex items-center justify-between mb-6">
          <h3 className="mono-label text-gray-300">Active Incident Playbook</h3>
          <span className="text-[10px] font-mono bg-accent/20 text-accent border border-accent/30 px-3 py-1 uppercase tracking-widest rounded">
            Execution Required
          </span>
        </div>
        
        <div className="space-y-4">
          
          {/* Containment Phase */}
          <div className="bg-surface border border-hairline rounded overflow-hidden">
            <div className="bg-base border-b border-hairline px-6 py-4 flex items-center gap-3">
              <Crosshair className="w-5 h-5 text-red-500" />
              <h4 className="font-display font-bold text-white uppercase tracking-wider text-sm">Phase 1: Containment</h4>
            </div>
            <div className="p-6">
              <ul className="space-y-3">
                {analysis.response.containment && analysis.response.containment.length > 0 ? (
                  analysis.response.containment.map((action, i) => (
                    <li key={i} className="flex items-start group">
                      <div className="w-4 h-4 border border-gray-500 rounded-sm mt-0.5 mr-4 flex-shrink-0 group-hover:border-accent cursor-pointer transition-colors"></div>
                      <span className="text-sm text-gray-300 font-mono">{action}</span>
                    </li>
                  ))
                ) : (
                  <li className="text-sm font-mono text-gray-600 italic">No containment protocols prescribed.</li>
                )}
              </ul>
            </div>
          </div>
          
          {/* Investigation Phase */}
          <div className="bg-surface border border-hairline rounded overflow-hidden">
            <div className="bg-base border-b border-hairline px-6 py-4 flex items-center gap-3">
              <Search className="w-5 h-5 text-amber-500" />
              <h4 className="font-display font-bold text-white uppercase tracking-wider text-sm">Phase 2: Investigation & Root Cause</h4>
            </div>
            <div className="p-6">
              <ul className="space-y-3">
                {analysis.response.investigation && analysis.response.investigation.length > 0 ? (
                  analysis.response.investigation.map((action, i) => (
                    <li key={i} className="flex items-start group">
                      <div className="w-4 h-4 border border-gray-500 rounded-sm mt-0.5 mr-4 flex-shrink-0 group-hover:border-accent cursor-pointer transition-colors"></div>
                      <span className="text-sm text-gray-300 font-mono">{action}</span>
                    </li>
                  ))
                ) : (
                  <li className="text-sm font-mono text-gray-600 italic">No investigation protocols prescribed.</li>
                )}
              </ul>
            </div>
          </div>
          
          {/* Recovery Phase */}
          <div className="bg-surface border border-hairline rounded overflow-hidden">
            <div className="bg-base border-b border-hairline px-6 py-4 flex items-center gap-3">
              <RotateCcw className="w-5 h-5 text-green-500" />
              <h4 className="font-display font-bold text-white uppercase tracking-wider text-sm">Phase 3: Recovery & Hardening</h4>
            </div>
            <div className="p-6">
              <ul className="space-y-3">
                {analysis.response.recovery && analysis.response.recovery.length > 0 ? (
                  analysis.response.recovery.map((action, i) => (
                    <li key={i} className="flex items-start group">
                      <div className="w-4 h-4 border border-gray-500 rounded-sm mt-0.5 mr-4 flex-shrink-0 group-hover:border-accent cursor-pointer transition-colors"></div>
                      <span className="text-sm text-gray-300 font-mono">{action}</span>
                    </li>
                  ))
                ) : (
                  <li className="text-sm font-mono text-gray-600 italic">No recovery protocols prescribed.</li>
                )}
              </ul>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};
