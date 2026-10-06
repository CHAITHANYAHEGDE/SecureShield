import { useState, useEffect } from 'react';
import { fetchSamples, analyzeSample } from './api';
import type { AnalysisResponse } from './api';
import { Activity, ShieldAlert, Cpu, Box, Share2, Layers, Crosshair } from 'lucide-react';
import { DashboardTab } from './components/DashboardTab';
import { EvidenceTab } from './components/EvidenceTab';
import { TimelineTab } from './components/TimelineTab';
import { MitreTab } from './components/MitreTab';
import { RiskTab } from './components/RiskTab';
import { ResearchTab } from './components/ResearchTab';

function App() {
  const [samples, setSamples] = useState<any[]>([]);
  const [selectedSample, setSelectedSample] = useState<any>(null);
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [scrubberValue, setScrubberValue] = useState(100);

  useEffect(() => {
    fetchSamples().then(setSamples).catch(console.error);
  }, []);

  const runAnalysis = async () => {
    if (!selectedSample) return;
    setLoading(true);
    try {
      const data = await analyzeSample(selectedSample.id);
      setAnalysis(data);
    } catch (e) {
      console.error(e);
    }
    setLoading(false);
  };

  return (
    <div className="h-screen w-full flex flex-col bg-base text-gray-300 font-sans">
      <div className="flex-1 flex overflow-hidden">
        {/* Left Rail */}
        <div className="w-64 border-r border-hairline bg-surface flex flex-col">
          <div className="p-4 border-b border-hairline">
            <h1 className="font-display text-xl text-white font-bold tracking-wide">SecureShield</h1>
            <p className="mono-label mt-1">Research Case File</p>
          </div>
          <div className="p-4 flex-1 overflow-y-auto">
            <h2 className="mono-label mb-2">Select Sample</h2>
            <select 
              className="w-full bg-base border border-hairline rounded p-2 mb-4 text-sm font-mono"
              onChange={(e) => setSelectedSample(samples.find(s => s.id === e.target.value))}
            >
              <option value="">-- Choose Sample --</option>
              {samples.map(s => (
                <option key={s.id} value={s.id}>Sample {s.id} ({s.class})</option>
              ))}
            </select>
            <button 
              onClick={runAnalysis}
              disabled={!selectedSample || loading}
              className="w-full py-2 bg-accent text-black font-bold rounded mb-6 uppercase text-sm tracking-wide disabled:opacity-50"
            >
              {loading ? 'Analyzing...' : 'Run Analysis'}
            </button>
            
            <nav className="space-y-1">
              {[
                {id: 'dashboard', label: 'Dashboard', icon: Activity},
                {id: 'research', label: 'Research Results', icon: Activity},
                {id: 'malware', label: 'Malware Analysis', icon: Cpu},
                {id: 'evidence', label: 'Forensic Evidence', icon: Box},
                {id: 'timeline', label: 'Attack Timeline', icon: Layers},
                {id: 'mitre', label: 'MITRE ATT&CK', icon: Crosshair},
                {id: 'graph', label: 'Incident Graph', icon: Share2},
                {id: 'risk', label: 'Risk & Response', icon: ShieldAlert},
                {id: 'ablation', label: 'Ablation', icon: Activity},
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center px-3 py-2 text-sm rounded ${activeTab === tab.id ? 'bg-accent/10 text-accent border border-accent/20' : 'hover:bg-hairline text-gray-400'}`}
                >
                  <tab.icon className="w-4 h-4 mr-3" />
                  {tab.label}
                </button>
              ))}
            </nav>
          </div>
        </div>

        {/* Center Canvas */}
        <div className="flex-1 overflow-y-auto p-8 relative">
           {/* Render appropriate component based on activeTab */}
           {loading ? (
             <div className="h-full flex items-center justify-center">
                <p className="font-mono animate-pulse text-accent">Executing Pipeline...</p>
             </div>
           ) : analysis || activeTab === 'research' ? (
             <div className="max-w-5xl mx-auto pb-16">
               <h2 className="font-display text-3xl text-white mb-6 capitalize">{activeTab.replace('-', ' ')}</h2>
               
               {activeTab === 'dashboard' && analysis && <DashboardTab analysis={analysis} />}
               {activeTab === 'evidence' && analysis && <EvidenceTab analysis={analysis} />}
               {activeTab === 'timeline' && analysis && <TimelineTab analysis={analysis} scrubberValue={scrubberValue} />}
               {activeTab === 'mitre' && analysis && <MitreTab analysis={analysis} />}
               {activeTab === 'risk' && analysis && <RiskTab analysis={analysis} />}
               {activeTab === 'research' && <ResearchTab />}
               
               {/* Fallback for other tabs */}
               {['malware', 'graph', 'ablation'].includes(activeTab) && analysis && (
                 <pre className="text-xs bg-surface p-4 border border-hairline rounded overflow-auto mt-4">
                   {JSON.stringify(analysis, null, 2)}
                 </pre>
               )}
             </div>
           ) : (
             <div className="h-full flex items-center justify-center text-gray-500 font-mono">
                Select a sample and run analysis
             </div>
           )}
        </div>
        
      </div>

      {/* Scrubber */}
      {analysis && (
        <div className="h-16 border-t border-hairline bg-surface flex items-center px-8 shrink-0">
           <span className="mono-label mr-4 w-32">Timeline Scrubber</span>
           <input 
             type="range" 
             min="0" 
             max="100" 
             value={scrubberValue} 
             onChange={(e) => setScrubberValue(Number(e.target.value))}
             className="flex-1" 
           />
        </div>
      )}
    </div>
  );
}

export default App;
