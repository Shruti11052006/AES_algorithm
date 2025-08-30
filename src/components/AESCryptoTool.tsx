import React, { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { AlertCircle, Copy, Key, Lock, Unlock, Zap } from 'lucide-react';
import { toast } from 'sonner';

interface EncryptRequest {
  plaintext: string;
  mode: string;
  padding: string;
  key_size: number;
  key: string;
  iv?: string;
}

interface DecryptRequest {
  ciphertext: string;
  mode: string;
  padding: string;
  key_size: number;
  key: string;
  iv?: string;
}

const AESCryptoTool = () => {
  const [encryptForm, setEncryptForm] = useState<EncryptRequest>({
    plaintext: '',
    mode: 'ECB',
    padding: 'PKCS7',
    key_size: 128,
    key: '',
    iv: ''
  });

  const [decryptForm, setDecryptForm] = useState<DecryptRequest>({
    ciphertext: '',
    mode: 'ECB',
    padding: 'PKCS7',
    key_size: 128,
    key: '',
    iv: ''
  });

  const [encryptResult, setEncryptResult] = useState<string>('');
  const [decryptResult, setDecryptResult] = useState<string>('');
  const [loading, setLoading] = useState<{ encrypt: boolean; decrypt: boolean }>({
    encrypt: false,
    decrypt: false
  });
  const [errors, setErrors] = useState<{ encrypt: string; decrypt: string }>({
    encrypt: '',
    decrypt: ''
  });

  const generateRandomHex = (length: number) => {
    const bytes = new Uint8Array(length / 2);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success('Copied to clipboard!');
    } catch (err) {
      toast.error('Failed to copy to clipboard');
    }
  };

  const validateHex = (value: string, expectedLength?: number) => {
    const hexRegex = /^[0-9A-Fa-f]*$/;
    if (!hexRegex.test(value)) return false;
    if (expectedLength && value.length !== expectedLength) return false;
    return true;
  };

  const handleEncrypt = async () => {
    setLoading(prev => ({ ...prev, encrypt: true }));
    setErrors(prev => ({ ...prev, encrypt: '' }));

    // Validation
    if (!encryptForm.plaintext) {
      setErrors(prev => ({ ...prev, encrypt: 'Plaintext is required' }));
      setLoading(prev => ({ ...prev, encrypt: false }));
      return;
    }

    if (!encryptForm.key) {
      setErrors(prev => ({ ...prev, encrypt: 'Key is required' }));
      setLoading(prev => ({ ...prev, encrypt: false }));
      return;
    }

    const keyLength = encryptForm.key_size / 4; // hex chars needed
    if (!validateHex(encryptForm.key, keyLength)) {
      setErrors(prev => ({ ...prev, encrypt: `Key must be ${keyLength} hex characters` }));
      setLoading(prev => ({ ...prev, encrypt: false }));
      return;
    }

    if (encryptForm.mode === 'CBC' && (!encryptForm.iv || !validateHex(encryptForm.iv, 32))) {
      setErrors(prev => ({ ...prev, encrypt: 'IV must be 32 hex characters for CBC mode' }));
      setLoading(prev => ({ ...prev, encrypt: false }));
      return;
    }

    try {
      const payload = { ...encryptForm };
      if (encryptForm.mode === 'ECB') {
        delete payload.iv;
      }

      const response = await fetch('http://localhost:5000/encrypt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (response.ok) {
        setEncryptResult(data.ciphertext);
        toast.success('Encryption successful!');
      } else {
        setErrors(prev => ({ ...prev, encrypt: data.error }));
        toast.error('Encryption failed');
      }
    } catch (error) {
      setErrors(prev => ({ ...prev, encrypt: 'Network error. Is the Flask server running?' }));
      toast.error('Connection error');
    }

    setLoading(prev => ({ ...prev, encrypt: false }));
  };

  const handleDecrypt = async () => {
    setLoading(prev => ({ ...prev, decrypt: true }));
    setErrors(prev => ({ ...prev, decrypt: '' }));

    // Validation
    if (!decryptForm.ciphertext) {
      setErrors(prev => ({ ...prev, decrypt: 'Ciphertext is required' }));
      setLoading(prev => ({ ...prev, decrypt: false }));
      return;
    }

    if (!decryptForm.key) {
      setErrors(prev => ({ ...prev, decrypt: 'Key is required' }));
      setLoading(prev => ({ ...prev, decrypt: false }));
      return;
    }

    const keyLength = decryptForm.key_size / 4;
    if (!validateHex(decryptForm.key, keyLength)) {
      setErrors(prev => ({ ...prev, decrypt: `Key must be ${keyLength} hex characters` }));
      setLoading(prev => ({ ...prev, decrypt: false }));
      return;
    }

    if (!validateHex(decryptForm.ciphertext)) {
      setErrors(prev => ({ ...prev, decrypt: 'Ciphertext must be valid hex' }));
      setLoading(prev => ({ ...prev, decrypt: false }));
      return;
    }

    if (decryptForm.mode === 'CBC' && (!decryptForm.iv || !validateHex(decryptForm.iv, 32))) {
      setErrors(prev => ({ ...prev, decrypt: 'IV must be 32 hex characters for CBC mode' }));
      setLoading(prev => ({ ...prev, decrypt: false }));
      return;
    }

    try {
      const payload = { ...decryptForm };
      if (decryptForm.mode === 'ECB') {
        delete payload.iv;
      }

      const response = await fetch('http://localhost:5000/decrypt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (response.ok) {
        setDecryptResult(data.plaintext);
        toast.success('Decryption successful!');
      } else {
        setErrors(prev => ({ ...prev, decrypt: data.error }));
        toast.error('Decryption failed');
      }
    } catch (error) {
      setErrors(prev => ({ ...prev, decrypt: 'Network error. Is the Flask server running?' }));
      toast.error('Connection error');
    }

    setLoading(prev => ({ ...prev, decrypt: false }));
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-card p-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <div className="p-3 rounded-full bg-gradient-to-r from-primary to-accent">
              <Key className="w-8 h-8 text-primary-foreground" />
            </div>
            <h1 className="text-4xl font-bold bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
              AES Crypto Tool
            </h1>
          </div>
          <p className="text-muted-foreground text-lg">
            Advanced Encryption Standard (AES) encryption and decryption utility
          </p>
        </div>

        <Tabs defaultValue="encrypt" className="w-full">
          <TabsList className="grid w-full grid-cols-2 mb-8 bg-card border border-border">
            <TabsTrigger value="encrypt" className="flex items-center gap-2">
              <Lock className="w-4 h-4" />
              Encrypt
            </TabsTrigger>
            <TabsTrigger value="decrypt" className="flex items-center gap-2">
              <Unlock className="w-4 h-4" />
              Decrypt
            </TabsTrigger>
          </TabsList>

          <TabsContent value="encrypt">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Encrypt Form */}
              <Card className="border-border bg-gradient-to-br from-card to-card/80">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Lock className="w-5 h-5 text-primary" />
                    Encryption Parameters
                  </CardTitle>
                  <CardDescription>
                    Configure your AES encryption settings
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label htmlFor="plaintext">Plaintext</Label>
                    <Textarea
                      id="plaintext"
                      placeholder="Enter text to encrypt..."
                      value={encryptForm.plaintext}
                      onChange={(e) => setEncryptForm(prev => ({ ...prev, plaintext: e.target.value }))}
                      className="min-h-[100px] font-mono"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="encrypt-mode">Mode</Label>
                      <Select value={encryptForm.mode} onValueChange={(value) => setEncryptForm(prev => ({ ...prev, mode: value }))}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="ECB">ECB</SelectItem>
                          <SelectItem value="CBC">CBC</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div>
                      <Label htmlFor="encrypt-padding">Padding</Label>
                      <Select value={encryptForm.padding} onValueChange={(value) => setEncryptForm(prev => ({ ...prev, padding: value }))}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="PKCS7">PKCS7</SelectItem>
                          <SelectItem value="ZEROPADDING">Zero Padding</SelectItem>
                          <SelectItem value="NOPADDING">No Padding</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div>
                    <Label htmlFor="encrypt-keysize">Key Size</Label>
                    <Select value={encryptForm.key_size.toString()} onValueChange={(value) => setEncryptForm(prev => ({ ...prev, key_size: parseInt(value) }))}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="128">128 bits</SelectItem>
                        <SelectItem value="192">192 bits</SelectItem>
                        <SelectItem value="256">256 bits</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <Label htmlFor="encrypt-key">Key (Hex)</Label>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => setEncryptForm(prev => ({ ...prev, key: generateRandomHex(prev.key_size / 4) }))}
                      >
                        <Zap className="w-3 h-3 mr-1" />
                        Generate
                      </Button>
                    </div>
                    <Input
                      id="encrypt-key"
                      placeholder={`${encryptForm.key_size / 4} hex characters`}
                      value={encryptForm.key}
                      onChange={(e) => setEncryptForm(prev => ({ ...prev, key: e.target.value }))}
                      className="font-mono"
                    />
                  </div>

                  {encryptForm.mode === 'CBC' && (
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Label htmlFor="encrypt-iv">IV (Hex)</Label>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => setEncryptForm(prev => ({ ...prev, iv: generateRandomHex(32) }))}
                        >
                          <Zap className="w-3 h-3 mr-1" />
                          Generate
                        </Button>
                      </div>
                      <Input
                        id="encrypt-iv"
                        placeholder="32 hex characters"
                        value={encryptForm.iv}
                        onChange={(e) => setEncryptForm(prev => ({ ...prev, iv: e.target.value }))}
                        className="font-mono"
                      />
                    </div>
                  )}

                  {errors.encrypt && (
                    <div className="flex items-center gap-2 text-destructive text-sm">
                      <AlertCircle className="w-4 h-4" />
                      {errors.encrypt}
                    </div>
                  )}

                  <Button 
                    onClick={handleEncrypt} 
                    disabled={loading.encrypt}
                    className="w-full bg-gradient-to-r from-primary to-accent hover:from-primary/90 hover:to-accent/90"
                  >
                    {loading.encrypt ? 'Encrypting...' : 'Encrypt'}
                  </Button>
                </CardContent>
              </Card>

              {/* Encrypt Result */}
              <Card className="border-border bg-gradient-to-br from-card to-card/80">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Key className="w-5 h-5 text-success" />
                    Encryption Result
                  </CardTitle>
                  <CardDescription>
                    Your encrypted ciphertext
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {encryptResult ? (
                    <div className="space-y-4">
                      <div>
                        <Label>Ciphertext (Hex)</Label>
                        <div className="relative">
                          <Textarea
                            value={encryptResult}
                            readOnly
                            className="min-h-[200px] font-mono text-success bg-success/10 border-success/20"
                          />
                          <Button
                            variant="outline"
                            size="sm"
                            className="absolute top-2 right-2"
                            onClick={() => copyToClipboard(encryptResult)}
                          >
                            <Copy className="w-3 h-3" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center text-muted-foreground py-8">
                      No encryption result yet. Fill in the form and click encrypt.
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="decrypt">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Decrypt Form */}
              <Card className="border-border bg-gradient-to-br from-card to-card/80">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Unlock className="w-5 h-5 text-primary" />
                    Decryption Parameters
                  </CardTitle>
                  <CardDescription>
                    Configure your AES decryption settings
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label htmlFor="ciphertext">Ciphertext (Hex)</Label>
                    <Textarea
                      id="ciphertext"
                      placeholder="Enter hex ciphertext to decrypt..."
                      value={decryptForm.ciphertext}
                      onChange={(e) => setDecryptForm(prev => ({ ...prev, ciphertext: e.target.value }))}
                      className="min-h-[100px] font-mono"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="decrypt-mode">Mode</Label>
                      <Select value={decryptForm.mode} onValueChange={(value) => setDecryptForm(prev => ({ ...prev, mode: value }))}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="ECB">ECB</SelectItem>
                          <SelectItem value="CBC">CBC</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div>
                      <Label htmlFor="decrypt-padding">Padding</Label>
                      <Select value={decryptForm.padding} onValueChange={(value) => setDecryptForm(prev => ({ ...prev, padding: value }))}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="PKCS7">PKCS7</SelectItem>
                          <SelectItem value="ZEROPADDING">Zero Padding</SelectItem>
                          <SelectItem value="NOPADDING">No Padding</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div>
                    <Label htmlFor="decrypt-keysize">Key Size</Label>
                    <Select value={decryptForm.key_size.toString()} onValueChange={(value) => setDecryptForm(prev => ({ ...prev, key_size: parseInt(value) }))}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="128">128 bits</SelectItem>
                        <SelectItem value="192">192 bits</SelectItem>
                        <SelectItem value="256">256 bits</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label htmlFor="decrypt-key">Key (Hex)</Label>
                    <Input
                      id="decrypt-key"
                      placeholder={`${decryptForm.key_size / 4} hex characters`}
                      value={decryptForm.key}
                      onChange={(e) => setDecryptForm(prev => ({ ...prev, key: e.target.value }))}
                      className="font-mono"
                    />
                  </div>

                  {decryptForm.mode === 'CBC' && (
                    <div>
                      <Label htmlFor="decrypt-iv">IV (Hex)</Label>
                      <Input
                        id="decrypt-iv"
                        placeholder="32 hex characters"
                        value={decryptForm.iv}
                        onChange={(e) => setDecryptForm(prev => ({ ...prev, iv: e.target.value }))}
                        className="font-mono"
                      />
                    </div>
                  )}

                  {errors.decrypt && (
                    <div className="flex items-center gap-2 text-destructive text-sm">
                      <AlertCircle className="w-4 h-4" />
                      {errors.decrypt}
                    </div>
                  )}

                  <Button 
                    onClick={handleDecrypt} 
                    disabled={loading.decrypt}
                    className="w-full bg-gradient-to-r from-primary to-accent hover:from-primary/90 hover:to-accent/90"
                  >
                    {loading.decrypt ? 'Decrypting...' : 'Decrypt'}
                  </Button>
                </CardContent>
              </Card>

              {/* Decrypt Result */}
              <Card className="border-border bg-gradient-to-br from-card to-card/80">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Unlock className="w-5 h-5 text-success" />
                    Decryption Result
                  </CardTitle>
                  <CardDescription>
                    Your decrypted plaintext
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {decryptResult ? (
                    <div className="space-y-4">
                      <div>
                        <Label>Plaintext</Label>
                        <div className="relative">
                          <Textarea
                            value={decryptResult}
                            readOnly
                            className="min-h-[200px] font-mono text-success bg-success/10 border-success/20"
                          />
                          <Button
                            variant="outline"
                            size="sm"
                            className="absolute top-2 right-2"
                            onClick={() => copyToClipboard(decryptResult)}
                          >
                            <Copy className="w-3 h-3" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center text-muted-foreground py-8">
                      No decryption result yet. Fill in the form and click decrypt.
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default AESCryptoTool;