require 'json'

module Jekyll
    class CategoryPageGenerator < Generator
      safe true
  
      def generate(site)
        # Grab the latest metadata directly from the file system
        modules = JSON.load(File.open("../db/modules_metadata_base.json"))
        modules = modules.slice(*modules.keys.take(10))
        dir = "modules"

        module_pages = modules.map do |(name, metadata)|
          ModulePage.new(site, site.source, dir, name, metadata)
        end
        
        site.pages.concat(module_pages)
        site.pages << ModuleIndex.new(site, site.source, dir, module_pages)
      end
    end
  
    class ModuleIndex < Page
      def initialize(site, base, dir, module_pages)
        @site = site
        @base = base
        @dir  = dir
        @name = "index.html"

        self.process(@name)
        self.read_yaml(File.join(base, '_layouts'), 'modules_index.html')
        self.data['title'] = "Modules"
        self.data['module_pages'] = module_pages
      end      
    end

    class ModulePage < Page
      def initialize(site, base, dir, name, metadata)
        @site = site
        @base = base
        @dir  = dir
        @name = "#{name}.html"

        self.process(@name)
        self.read_yaml(File.join(base, '_layouts'), 'modules.html')
        self.data['metadata'] = metadata
        self.data['title'] = metadata['name']
      end
    end
  end