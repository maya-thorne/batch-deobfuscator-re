/**
 * BatchGuard Pro Obfuscation Engine
 * Senior Developer Implementation
 */

const HEADER_BYTES = new Uint8Array([0xFF, 0xFE, 0x26, 0x63, 0x6C, 0x73, 0x0D, 0x0A]);


/**
 * Advanced Variable Scrambling
 * Identifies user-defined SET variables and replaces them with random hex IDs.
 */
export const scrambleVariables = (content) => {
  const systemVars = new Set([
    'path', 'temp', 'tmp', 'windir', 'comspec', 'os', 'date', 'time',
    'random', 'errorlevel', 'cmdextversion', 'cmdcmdline', 'ps1',
    'username', 'computername', 'userprofile', 'appdata', 'localappdata'
  ]);

  // 1. Identify all variables that are SET by the user
  const setRegex = /set\s+([a-zA-Z0-9_\-]+)=/gi;
  const userVars = new Set();
  let match;
  while ((match = setRegex.exec(content)) !== null) {
    const varName = match[1].toLowerCase();
    if (!systemVars.has(varName)) {
      userVars.add(match[1]); // Keep original casing for exact replacement
    }
  }

  // 2. Create a mapping to random hex strings
  const mapping = {};
  userVars.forEach(v => {
    // Generate a unique-looking hex string like _0x3f2a
    mapping[v] = `_0x${Math.floor(Math.random() * 0xFFFF).toString(16).padStart(4, '0')}`;
  });

  // 3. Perform replacements
  let scrambledContent = content;
  Object.keys(mapping).forEach(original => {
    const replacement = mapping[original];
    // Replace SET declarations
    const declRegex = new RegExp(`set\\s+${original}=`, 'gi');
    scrambledContent = scrambledContent.replace(declRegex, `set ${replacement}=`);
    
    // Replace usages: %var%, !var!
    const usageRegex = new RegExp(`%${original}%`, 'gi');
    scrambledContent = scrambledContent.replace(usageRegex, `%${replacement}%`);
    
    const delayedRegex = new RegExp(`!${original}!`, 'gi');
    scrambledContent = scrambledContent.replace(delayedRegex, `!${replacement}!`);
  });

  return scrambledContent;
};

export const obfuscateBatchFile = async (file, options = { scramble: false }) => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = () => {
      let content = new TextDecoder().decode(reader.result);
      
      // Apply Variable Scrambling if enabled
      if (options.scramble) {
        content = scrambleVariables(content);
      }

      // Encode back to bytes
      const fileBuffer = new TextEncoder().encode(content);
      const obfuscatedBuffer = new Uint8Array(HEADER_BYTES.length + fileBuffer.length);
      
      // Inject Header
      obfuscatedBuffer.set(HEADER_BYTES, 0);
      // Append content
      obfuscatedBuffer.set(fileBuffer, HEADER_BYTES.length);
      
      const blob = new Blob([obfuscatedBuffer], { type: 'application/x-bat' });
      const outputName = file.name.replace(/\.(bat|cmd)$/i, '') + '_obfuscated' + (file.name.match(/\.(bat|cmd)$/i)?.[0] || '.bat');
      
      resolve({
        blob,
        fileName: outputName,
        originalSize: file.size,
        newSize: obfuscatedBuffer.length
      });
    };
    
    reader.onerror = () => reject(new Error("Failed to read file"));
    reader.readAsArrayBuffer(file);
  });
};
