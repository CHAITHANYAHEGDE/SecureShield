import React, { useState } from 'react';
import type { AnalysisResponse } from '../api';
import { ProvenanceBadge } from './ProvenanceBadge';
import { ShieldAlert, ChevronDown, ChevronRight, CornerDownRight } from 'lucide-react';

interface Props {
  analysis: AnalysisResponse;
}

export const MitreTab: React.FC<Props> = ({ analysis }) => {
  const [expandedTechs, setExpandedTechs] = useState<Record<string, boolean>>({});

  const toggleTech = (id: string) => {
    setExpandedTechs(prev => ({...prev, [id]: !prev[id]}));
  };

  // Group by tactic
  const groupedMitre = analysis.mitre.reduce((acc, curr) => {
    const tactic = curr.tactic || 'Unknown Tactic';
    if (!acc[tactic]) acc[tactic] = [];
    acc[tactic].push(curr);
    return acc;
  }, {} as Record<string, typeof analysis.mitre>);

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex items-center justify-between border-b border-hairline pb-4">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 text-gray-400" />
          <h3 className="mono-label text-gray-300 m-0">ATT&CK Matrix Projection</h3>
        </div>
        <div className="text-[10px] font-mono text-accent uppercase tracking-widest border border-accent/30 bg-accent/10 px-3 py-1 rounded">
          NO EVIDENCE → NO TECHNIQUE
        </div>
      </div>

      <div className="space-y-8">
        {Object.entries(groupedMitre).length === 0 ? (
          <div className="bg-surface border border-hairline p-8 rounded text-center text-gray-500 font-mono italic">
            No MITRE ATT&CK techniques mapped for this incident.
          </div>
        ) : (
          Object.entries(groupedMitre).map(([tactic, techniques], i) => (
            <div key={i} className="font-mono text-sm">
              <div className="flex items-center gap-2 mb-3 text-white font-bold uppercase tracking-wider text-base">
                {tactic}
              </div>
              
              <div className="pl-6 space-y-4 border-l border-hairline ml-2">
                {techniques.map((tech, j) => {
                  const techIdKey = `${tactic}-${tech.technique_id}-${j}`;
                  const isExpanded = !!expandedTechs[techIdKey];
                  
                  return (
                  <div key={j} className="relative">
                    <div 
                      className="flex items-center gap-2 cursor-pointer group"
                      onClick={() => toggleTech(techIdKey)}
                    >
                      <span className="absolute -left-6 bg-base text-hairline"><CornerDownRight className="w-4 h-4" /></span>
                      {isExpanded ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
                      <span className="text-accent font-bold">{tech.technique_id}</span>
                      <span className="text-gray-300 group-hover:text-white transition-colors">{tech.sub_technique}</span>
                    </div>
                    
                    {isExpanded && (
                      <div className="pl-6 mt-3 space-y-2 border-l border-hairline ml-2 relative">
                        
                        <div className="flex items-center gap-2 text-xs">
                          <span className="absolute -left-6 bg-base text-hairline"><CornerDownRight className="w-4 h-4" /></span>
                          <span className="text-gray-500 w-24">Confidence:</span>
                          <span className="text-white">{(tech.confidence * 100).toFixed(1)}%</span>
                        </div>
                        
                        <div className="flex items-center gap-2 text-xs">
                          <span className="absolute -left-6 bg-base text-hairline"><CornerDownRight className="w-4 h-4" /></span>
                          <span className="text-gray-500 w-24">Provenance:</span>
                          <ProvenanceBadge provenance={tech.provenance} />
                        </div>
                        
                        <div className="flex items-start gap-2 text-xs pt-1">
                          <span className="absolute -left-6 bg-base text-hairline mt-0.5"><CornerDownRight className="w-4 h-4" /></span>
                          <span className="text-gray-500 w-24 shrink-0">Evidence IDs:</span>
                          <div className="flex flex-wrap gap-1">
                            {tech.supporting_evidence_ids.length > 0 ? (
                              tech.supporting_evidence_ids.map(id => (
                                <span key={id} className="bg-surface border border-hairline text-gray-400 px-1.5 py-0.5 rounded">{id}</span>
                              ))
                            ) : (
                              <span className="text-severity-critical italic font-bold">MISSING EVIDENCE</span>
                            )}
                          </div>
                        </div>

                      </div>
                    )}
                  </div>
                )})}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
