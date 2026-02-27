document.getElementById('scanBtn').addEventListener('click', async () => {
  const statusDiv = document.getElementById('status');
  statusDiv.innerText = "Analyzing URL...";

  // Get current tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  try {
    const response = await fetch(`http://127.0.0.1:8000/analyze-runtime?url=${encodeURIComponent(tab.url)}`, {
      method: 'POST'
    });
    
    const result = await response.json();
    
    if (result.status === "success") {
      statusDiv.innerText = `Scan Complete! Found ${result.issues} issues. Check Supabase.`;
      statusDiv.style.color = "green";
    }
  } catch (error) {
    statusDiv.innerText = "Error: Backend Offline";
    statusDiv.style.color = "red";
  }
});