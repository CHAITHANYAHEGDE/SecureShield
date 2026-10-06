import { useState, useEffect } from 'react';
import { fetchSamples, analyzeSample } from './api';
import type { AnalysisResponse } from './api';
import { Shield, RefreshCw, Settings, Search } from 'lucide-react';
import { DashboardTab } from './components/DashboardTab';
import { EvidenceTab } from './components/EvidenceTab';
import { TimelineTab } from './components/TimelineTab';
import { MitreTab } from './components/MitreTab';
import { RiskTab } from './components/RiskTab';
import { ResearchTab } from './components/ResearchTab';
import { ProvenanceBadge } from './components/ProvenanceBadge';

function App() {
  const [samples, setSamples] = useState<any[]>([]);
  const [selectedSampleId, setSelectedSampleId] = useState<string>("");
  const [selectedSample, setSelectedSample] = useState<any>(null);
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [scrubberValue, setScrubberValue] = useState(100);

  useEffect(() => {
    fetchSamples().then(setSamples).catch(console.error);
  }, []);

  const handleSelectSample = async (id: string) => {
    setSelectedSampleId(id);
    const sample = samples.find(s => s.id === id);
    setSelectedSample(sample || null);
    
    if (sample) {
      setLoading(true);
      setActiveTab('overview');
      setAnalysis(null);
      try {
        const data = await analyzeSample(sample.id);
        setAnalysis(data);
      } catch (e) {
        console.error(e);
      }
      setLoading(false);
    }
  };

  const navItems = [
    {id: 'overview', label: 'Overview'},
    {id: 'evidence', label: 'Evidence'},
    {id: 'timeline', label: 'Timeline'},
    {id: 'mitre', label: 'ATT&CK'},
    {id: 'graph', label: 'Graph'},
    {id: 'risk', label: 'Risk & Response'},
  ];

  return (
    <div className="h-screen w-full flex flex-col bg-base text-gray-300 font-sans">
      {/* Top Header / Command Bar */}
      <header className="h-14 border-b border-hairline bg-surface flex items-center px-4 shrink-0">
        <div className="flex items-center gap-3 w-64 border-r border-hairline h-full">
           <Shield className="text-accent w-5 h-5" />
           <div>
             <h1 className="font-display text-white font-bold tracking-wide leading-none text-lg">SecureShield</h1>
             <p className="mono-label text-[8px] mt-1">SECURITY INVESTIGATION PLATFORM</p>
           </div>
        </div>
        
        {/* Center: Case Status */}
        <div className="flex-1 px-6 flex items-center gap-6">
          {analysis ? (
             <>
               <div className="flex items-center gap-2">
                 <span className="mono-label">Case:</span>
                 <span className="font-mono text-sm text-white">{selectedSample?.id || 'N/A'}</span>
               </div>
               <div className="flex items-center gap-2">
                 <span className="mono-label">Status:</span>
                 <span className="font-mono text-sm text-emerald-400">Complete</span>
               </div>
               <div className="flex items-center gap-2">
                 <span className="mono-label">Verdict:</span>
                 <span className={`font-mono text-sm font-bold ${analysis.prediction.label === 'malicious' ? 'text-severity-critical' : 'text-severity-low'}`}>
                   {analysis.prediction.label.toUpperCase()}
                 </span>
               </div>
               <div className="flex items-center gap-2">
                 <span className="mono-label">Confidence:</span>
                 <span className="font-mono text-sm text-white">{(analysis.prediction.confidence * 100).toFixed(1)}%</span>
               </div>
               <div className="ml-auto flex items-center gap-2">
                  <ProvenanceBadge provenance={analysis.prediction.provenance} />
               </div>
             </>
          ) : (
             <div className="mono-label text-gray-500">Awaiting Case Selection</div>
          )}
        </div>

        {/* Right: Actions */}
        <div className="w-48 border-l border-hairline h-full flex items-center justify-end px-4 gap-4">
           <button className="text-gray-400 hover:text-white transition-colors">
             <RefreshCw className="w-4 h-4" />
           </button>
           <button className="text-gray-400 hover:text-white transition-colors">
             <Settings className="w-4 h-4" />
           </button>
           <div className="text-xs font-mono text-gray-500 border border-hairline px-2 py-1 rounded bg-base">
             ID: {selectedSample?.id || '----'}
           </div>
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        {/* Minimal Left Sidebar for Navigation only */}
        <div className="w-64 border-r border-hairline bg-surface flex flex-col shrink-0">
           {/* Sample Selector moved to the top of navigation or integrated */}
           <div className="p-4 border-b border-hairline">
             <label className="mono-label block mb-2">Active Investigation</label>
             <div className="relative">
                <Search className="w-4 h-4 absolute left-2 top-2.5 text-gray-500" />
                <select 
                  className="w-full bg-base border border-hairline rounded pl-8 pr-2 py-2 text-sm font-mono appearance-none accent-focus text-white"
                  value={selectedSampleId}
                  onChange={(e) => handleSelectSample(e.target.value)}
                >
                  <option value="">-- Search Samples --</option>
                  {samples.map(s => (
                    <option key={s.id} value={s.id}>{s.id} ({s.class})</option>
                  ))}
                </select>
             </div>
           </div>

           <nav className="p-4 space-y-0.5 flex-1 overflow-y-auto">
             <div className="mono-label mb-3 mt-2">Investigation Steps</div>
             {navItems.map(tab => (
               <button
                 key={tab.id}
                 disabled={!analysis && tab.id !== 'overview'}
                 onClick={() => setActiveTab(tab.id)}
                 className={`w-full flex items-center px-3 py-2 text-sm rounded transition-colors ${
                   activeTab === tab.id 
                     ? 'bg-accent/10 text-accent font-medium' 
                     : 'text-gray-400 hover:text-white hover:bg-hairline disabled:opacity-30 disabled:hover:bg-transparent disabled:hover:text-gray-400'
                 }`}
               >
                 {tab.label}
               </button>
             ))}

             <div className="mono-label mb-3 mt-8">Research & Reference</div>
             <button
                 onClick={() => setActiveTab('research')}
                 className={`w-full flex items-center px-3 py-2 text-sm rounded transition-colors ${
                   activeTab === 'research' 
                     ? 'bg-accent/10 text-accent font-medium' 
                     : 'text-gray-400 hover:text-white hover:bg-hairline'
                 }`}
               >
                 Research Results
               </button>
           </nav>
        </div>

        {/* Main Canvas */}
        <div className="flex-1 overflow-y-auto relative bg-base">
          {loading ? (
             <div className="h-full w-full flex flex-col items-center justify-center">
                <div className="w-12 h-12 border-2 border-hairline border-t-accent rounded-full animate-spin mb-4"></div>
                <p className="font-mono text-sm text-gray-400 animate-pulse">Running ML detection and evidence correlation...</p>
             </div>
          ) : !analysis && activeTab !== 'research' ? (
             <div className="h-full w-full flex items-center justify-center p-8">
                <div className="max-w-3xl w-full border border-hairline bg-surface p-12 rounded flex flex-col items-center text-center">
                   <Shield className="w-16 h-16 text-gray-700 mb-6" />
                   <h2 className="font-display text-2xl text-white mb-2">NEW INVESTIGATION</h2>
                   <p className="text-gray-400 mb-8 max-w-md">Select a dataset sample from the sidebar to begin analysis. SecureShield will run the sample through a multi-stage ML and forensic correlation pipeline.</p>
                   
                   <div className="flex items-center justify-center gap-2 font-mono text-[10px] text-gray-500 mb-12 flex-wrap uppercase tracking-wide">
                      <span className="px-2 py-1 bg-base border border-hairline rounded">ML Detection</span>
                      <span>→</span>
                      <span className="px-2 py-1 bg-base border border-hairline rounded">Forensic Evidence</span>
                      <span>→</span>
                      <span className="px-2 py-1 bg-base border border-hairline rounded">Event Correlation</span>
                      <span>→</span>
                      <span className="px-2 py-1 bg-base border border-hairline rounded">Behavior Analysis</span>
                      <span>→</span>
                      <span className="px-2 py-1 bg-base border border-hairline rounded">MITRE ATT&CK</span>
                      <span>→</span>
                      <span className="px-2 py-1 bg-base border border-hairline rounded">Risk & Response</span>
                   </div>

                   <div className="grid grid-cols-3 gap-6 text-left w-full">
                     <div className="bg-base border border-hairline p-5 rounded">
                       <h3 className="font-mono text-xs text-white mb-2 uppercase tracking-wide">Detection</h3>
                       <p className="text-xs text-gray-400 leading-relaxed">Model prediction, confidence scores, and SHAP explainability for behavioral features.</p>
                     </div>
                     <div className="bg-base border border-hairline p-5 rounded">
                       <h3 className="font-mono text-xs text-white mb-2 uppercase tracking-wide">Evidence</h3>
                       <p className="text-xs text-gray-400 leading-relaxed">Derived forensic indicators, provenance tracking, and explicit temporal correlation.</p>
                     </div>
                     <div className="bg-base border border-hairline p-5 rounded">
                       <h3 className="font-mono text-xs text-white mb-2 uppercase tracking-wide">Actionable Risk</h3>
                       <p className="text-xs text-gray-400 leading-relaxed">MITRE mapping, risk scoring, and prioritized incident response recommendations.</p>
                     </div>
                   </div>
                </div>
             </div>
          ) : (
             <div className="p-8 max-w-7xl mx-auto pb-24">
                {activeTab === 'overview' && analysis && <DashboardTab analysis={analysis} />}
                {activeTab === 'evidence' && analysis && <EvidenceTab analysis={analysis} />}
                {activeTab === 'timeline' && analysis && <TimelineTab analysis={analysis} scrubberValue={scrubberValue} />}
                {activeTab === 'mitre' && analysis && <MitreTab analysis={analysis} />}
                {activeTab === 'risk' && analysis && <RiskTab analysis={analysis} />}
                {activeTab === 'research' && <ResearchTab />}
                
                {/* Fallback for missing tabs */}
                {['graph'].includes(activeTab) && analysis && (
                  <div className="border border-hairline bg-surface p-4 rounded">
                    <h3 className="font-mono text-sm mb-4">Incident Graph</h3>
                    <p className="text-gray-400 text-sm mb-4">Interactive graph representation goes here.</p>
                    <pre className="text-[10px] text-gray-500 overflow-auto max-h-[600px] bg-base p-4 border border-hairline rounded">
                      {JSON.stringify(analysis, null, 2)}
                    </pre>
                  </div>
                )}
             </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
