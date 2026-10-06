import React from 'react';

export type Provenance = 'MEASURED' | 'DERIVED' | 'SIMULATED';

export const ProvenanceBadge: React.FC<{ provenance: Provenance }> = ({ provenance }) => {
  const getStyles = () => {
    switch (provenance) {
      case 'MEASURED':
        return 'bg-green-900/40 text-green-400 border-green-800/50';
      case 'DERIVED':
        return 'bg-amber-900/40 text-amber-400 border-amber-800/50';
      case 'SIMULATED':
        return 'bg-purple-900/40 text-purple-400 border-purple-800/50';
      default:
        return 'bg-gray-800 text-gray-400 border-gray-700';
    }
  };

  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase border tracking-wider ${getStyles()}`}>
      {provenance}
    </span>
  );
};
