import { GitHub } from "@mui/icons-material";
import { AppBar, Box, IconButton, Toolbar, Typography } from "@mui/material";
import CCQ from "./CCQ";

function App() {
  return (
    <main>
      <AppBar position="static">
        <Toolbar variant="dense">
          <Typography variant="h6" component="div" sx={{ mr: 1 }}>
            Query Demo
          </Typography>
          <Box sx={{ flexGrow: 1 }} />
          <IconButton
            href="https://github.com/wormholelabs-xyz/example-queries-demo"
            edge="end"
            color="inherit"
            sx={{ ml: 2 }}
          >
            <GitHub />
          </IconButton>
        </Toolbar>
      </AppBar>
      <Box m={2}>
        <CCQ />
      </Box>
    </main>
  );
}

export default App;
