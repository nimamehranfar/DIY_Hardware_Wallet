/**
 * Settings Store - Persisted settings with Zustand
 */
import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import AsyncStorage from '@react-native-async-storage/async-storage';

// Network options
export type NetworkType = 'devnet' | 'mainnet' | 'testnet';

// Currency options  
export type CurrencyType = 'USD' | 'EUR' | 'GBP';

// RPC endpoints
export const RPC_ENDPOINTS: Record<NetworkType, string> = {
    devnet: 'https://api.devnet.solana.com',
    mainnet: 'https://api.mainnet-beta.solana.com',
    testnet: 'https://api.testnet.solana.com',
};

// Explorer URLs
export const EXPLORER_URLS: Record<NetworkType, string> = {
    devnet: 'https://explorer.solana.com/?cluster=devnet',
    mainnet: 'https://explorer.solana.com',
    testnet: 'https://explorer.solana.com/?cluster=testnet',
};

interface SettingsState {
    // Network & Connection
    network: NetworkType;
    deviceIP: string;
    connectionTimeout: number; // seconds

    // Security
    biometricEnabled: boolean;
    sessionTimeout: number; // minutes
    largeAmountConfirmation: boolean;
    largeAmountThreshold: number; // SOL

    // Display
    currency: CurrencyType;
    showFullAddress: boolean;
    darkMode: boolean;

    // Actions
    setNetwork: (network: NetworkType) => void;
    setDeviceIP: (ip: string) => void;
    setConnectionTimeout: (seconds: number) => void;
    setBiometricEnabled: (enabled: boolean) => void;
    setSessionTimeout: (minutes: number) => void;
    setLargeAmountConfirmation: (enabled: boolean) => void;
    setLargeAmountThreshold: (amount: number) => void;
    setCurrency: (currency: CurrencyType) => void;
    setShowFullAddress: (full: boolean) => void;
    setDarkMode: (dark: boolean) => void;

    // Computed
    getRpcUrl: () => string;
    getExplorerUrl: () => string;
}

export const useSettingsStore = create<SettingsState>()(
    persist(
        (set, get) => ({
            // Default values
            network: 'devnet',
            deviceIP: '',
            connectionTimeout: 30,
            biometricEnabled: false,
            sessionTimeout: 5,
            largeAmountConfirmation: true,
            largeAmountThreshold: 1.0,
            currency: 'USD',
            showFullAddress: false,
            darkMode: true,

            // Actions
            setNetwork: (network) => set({ network }),
            setDeviceIP: (deviceIP) => set({ deviceIP }),
            setConnectionTimeout: (connectionTimeout) => set({ connectionTimeout }),
            setBiometricEnabled: (biometricEnabled) => set({ biometricEnabled }),
            setSessionTimeout: (sessionTimeout) => set({ sessionTimeout }),
            setLargeAmountConfirmation: (largeAmountConfirmation) => set({ largeAmountConfirmation }),
            setLargeAmountThreshold: (largeAmountThreshold) => set({ largeAmountThreshold }),
            setCurrency: (currency) => set({ currency }),
            setShowFullAddress: (showFullAddress) => set({ showFullAddress }),
            setDarkMode: (darkMode) => set({ darkMode }),

            // Computed
            getRpcUrl: () => RPC_ENDPOINTS[get().network],
            getExplorerUrl: () => EXPLORER_URLS[get().network],
        }),
        {
            name: 'wallet-settings',
            storage: createJSONStorage(() => AsyncStorage),
        }
    )
);

// Currency symbols
export const CURRENCY_SYMBOLS: Record<CurrencyType, string> = {
    USD: '$',
    EUR: '€',
    GBP: '£',
};

// Approximate exchange rates from USD (updated periodically)
// In production, fetch from API
export const USD_EXCHANGE_RATES: Record<CurrencyType, number> = {
    USD: 1.0,
    EUR: 0.92,  // 1 USD = 0.92 EUR
    GBP: 0.79,  // 1 USD = 0.79 GBP
};

// Convert USD to selected currency
export const convertCurrency = (usdAmount: number, currency: CurrencyType): number => {
    return usdAmount * USD_EXCHANGE_RATES[currency];
};
