import React from 'react';
import type { AnalysisResponse } from '../api';
import { ProvenanceBadge } from './ProvenanceBadge';

interface Props {
  analysis: AnalysisResponse;
}

export const MitreTab: React.FC<Props> = ({ analysis }) => {
  // Group by tactic
  const groupedMitre = analysis.mitre.reduce((acc, curr) => {
    const tactic = curr.tactic || 'Unknown Tactic';
    if (!acc[tactic]) acc[tactic] = [];
    acc[tactic].push(curr);
    return acc;
  }, {} as Record<string, typeof analysis.mitre>);

  return (
    <div className="space-y-6">
      {Object.entries(groupedMitre).length === 0 ? (
        <div className="bg-surface border border-hairline p-8 rounded text-center text-gray-500 font-mono italic">
          No MITRE ATT&CK techniques mapped for this incident.
        </div>
      ) : (
        Object.entries(groupedMitre).map(([tactic, techniques], i) => (
          <div key={i} className="bg-surface border border-hairline rounded overflow-hidden">
            <div className="bg-hairline/50 px-5 py-3 border-b border-hairline flex justify-between items-center">
              <h3 className="font-display font-bold text-white uppercase tracking-wider">{tactic}</h3>
              <span className="text-xs font-mono text-gray-400 bg-base px-2 py-1 rounded">
                {techniques.length} Technique{techniques.length !== 1 ? 's' : ''}
              </span>
            </div>
            
            <div className="divide-y divide-hairline">
              {techniques.map((tech, j) => (
                <div key={j} className="p-5">
                  <div className="flex justify-between items-start mb-3">
                    <div className="flex items-center space-x-3">
                      <span className="text-sm font-mono font-bold text-accent">{tech.technique_id}</span>
                      <span className="text-sm text-white">{tech.sub_technique}</span>
                    </div>
                    <ProvenanceBadge provenance={tech.provenance} />
                  </div>
                  
                  <div className="mb-4">
                    <div className="text-xs font-mono text-gray-500 mb-1">Mapping Confidence: {(tech.confidence * 100).toFixed(1)}%</div>
                    {/* Width of progress bar based on confidence */}
                    <div className="w-full bg-base h-1.5 rounded-full overflow-hidden">
                       <div 
                         className="h-full bg-accent rounded-full" 
                         style={{ width: `${tech.confidence * 100}%` }}
                       ></div>
                    </div>
                  </div>
                  
                  <div>
                    <span className="text-xs font-mono text-gray-500 block mb-2">Supporting Evidence:</span>
                    <div className="flex flex-wrap gap-2">
                      {tech.supporting_evidence_ids.map(id => (
                        <span key={id} className="text-[10px] font-mono bg-base border border-hairline text-gray-400 px-2 py-1 rounded">{id}</span>
                      ))}
                      {tech.supporting_evidence_ids.length === 0 && (
                        <span className="text-xs font-mono text-gray-600 italic">None</span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
};
