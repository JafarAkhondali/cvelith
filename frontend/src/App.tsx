import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import { LoginModal } from "@/components/LoginModal";
import Dashboard from "./pages/Dashboard";
import CVEDetail from "./pages/CVEDetail";
import NotFound from "./pages/NotFound";
import { useEffect } from "react";

const queryClient = new QueryClient();

// Component to handle global 401 errors
const AuthHandler = () => {
  const { setShowLoginModal } = useAuth();

  useEffect(() => {
    const handleUnauthorized = () => {
      setShowLoginModal(true);
    };

    window.addEventListener('auth:unauthorized', handleUnauthorized);
    return () => {
      window.removeEventListener('auth:unauthorized', handleUnauthorized);
    };
  }, [setShowLoginModal]);

  return null;
};

const AppContent = () => {
  const { showLoginModal, setShowLoginModal } = useAuth();
  const location = useLocation();
  const isCveDetailPage = location.pathname.startsWith('/cve/');

  return (
    <>
      <AuthHandler />
      <LoginModal 
        open={showLoginModal} 
        onOpenChange={setShowLoginModal}
        required={true}
      />
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/cve/:id" element={<CVEDetail />} />
        {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </>
  );
};

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AuthProvider>
          <AppContent />
        </AuthProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
