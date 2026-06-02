/* HoneyMind — app shell : routing + thème */
function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem('hm-theme') || 'dark');
  const [route, setRoute] = useState(() => {
    try { return JSON.parse(localStorage.getItem('hm-route')) || { name: 'dashboard' }; }
    catch (e) { return { name: 'dashboard' }; }
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('hm-theme', theme);
  }, [theme]);

  useEffect(() => {
    localStorage.setItem('hm-route', JSON.stringify(route));
    const m = document.querySelector('.main');
    if (m) m.scrollTop = 0;
    window.scrollTo(0, 0);
  }, [route]);

  const go = (r) => setRoute(r);
  const themeToggle = <ThemeToggle theme={theme} setTheme={setTheme} />;

  let view;
  if (route.name === 'campaigns') view = <CampaignsView go={go} themeToggle={themeToggle} />;
  else if (route.name === 'campaign') view = <CampaignDetailView id={route.id} go={go} themeToggle={themeToggle} />;
  else view = <DashboardView themeToggle={themeToggle} />;

  return (
    <div className="app">
      <Sidebar route={route} go={go} />
      {view}
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
